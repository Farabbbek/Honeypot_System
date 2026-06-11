import logging
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import desc, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DBSession

from ip_enrichment import IPEnrichmentService
from models import IPIntel, Session

logger = logging.getLogger(__name__)

UNKNOWN_COUNTRY_VALUES = {"", "unknown", "n/a", "none", "null"}
IP_INTEL_FIELDS = {
    "ip",
    "country_code",
    "country_name",
    "city",
    "latitude",
    "longitude",
    "asn",
    "org_name",
    "abuse_confidence_score",
    "total_reports",
    "last_reported_at",
    "is_tor",
    "is_vpn",
    "enriched_at",
}


def clean_country(country: Any) -> str | None:
    if country is None:
        return None
    value = str(country).strip()
    if value.lower() in UNKNOWN_COUNTRY_VALUES:
        return None
    return value


def has_known_country(intel: IPIntel | None) -> bool:
    return bool(clean_country(getattr(intel, "country_name", None)))


def to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed != parsed:
        return None
    return parsed


def has_valid_lat_lng(lat: Any, lng: Any) -> bool:
    lat_value = to_float(lat)
    lng_value = to_float(lng)
    if lat_value is None or lng_value is None:
        return False
    if lat_value == 0 and lng_value == 0:
        return False
    return -90 <= lat_value <= 90 and -180 <= lng_value <= 180


def intel_has_valid_lat_lng(intel: IPIntel | None) -> bool:
    if intel is None:
        return False
    return has_valid_lat_lng(intel.latitude, intel.longitude)


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.replace(tzinfo=None)
    return None


def normalize_enrichment_payload(ip: str, data: dict[str, Any]) -> dict[str, Any]:
    payload = {key: data.get(key) for key in IP_INTEL_FIELDS if key in data}
    payload["ip"] = ip
    payload["country_name"] = clean_country(payload.get("country_name")) or "unknown"
    payload["latitude"] = to_float(payload.get("latitude"))
    payload["longitude"] = to_float(payload.get("longitude"))
    payload["last_reported_at"] = _parse_datetime(payload.get("last_reported_at"))
    payload["enriched_at"] = _parse_datetime(payload.get("enriched_at")) or datetime.utcnow()
    return payload


def upsert_ip_intel(db: DBSession, data: dict[str, Any]) -> IPIntel:
    stmt = insert(IPIntel).values(**data)
    stmt = stmt.on_conflict_do_update(
        index_elements=[IPIntel.ip],
        set_={key: value for key, value in data.items() if key != "ip"},
    ).returning(IPIntel)
    return db.execute(stmt).scalar_one()


def geo_session_counts(db: DBSession) -> dict[str, int]:
    rows = (
        db.query(Session.attacker_ip, IPIntel.country_name, IPIntel.latitude, IPIntel.longitude)
        .outerjoin(IPIntel, IPIntel.ip == Session.attacker_ip)
        .all()
    )
    return {
        "total_sessions": len(rows),
        "sessions_with_country": sum(1 for _, country, _, _ in rows if clean_country(country)),
        "sessions_with_valid_lat_lng": sum(
            1 for _, _, lat, lng in rows if has_valid_lat_lng(lat, lng)
        ),
    }


def recent_ips_needing_geo(
    db: DBSession,
    *,
    limit: int,
    refresh_after: timedelta,
    force: bool = False,
) -> list[str]:
    latest_ips = (
        db.query(
            Session.attacker_ip.label("ip"),
            func.max(Session.start_time).label("last_seen"),
        )
        .group_by(Session.attacker_ip)
        .subquery()
    )
    rows = (
        db.query(latest_ips.c.ip, latest_ips.c.last_seen, IPIntel)
        .outerjoin(IPIntel, IPIntel.ip == latest_ips.c.ip)
        .order_by(desc(latest_ips.c.last_seen))
        .all()
    )

    cutoff = datetime.utcnow() - refresh_after
    ips: list[str] = []
    for ip, _, intel in rows:
        if not ip:
            continue
        missing_geo = intel is None or not has_known_country(intel) or not intel_has_valid_lat_lng(intel)
        if not missing_geo:
            continue
        refreshed_recently = bool(intel and intel.enriched_at and intel.enriched_at >= cutoff)
        if force or not refreshed_recently:
            ips.append(ip)
        if len(ips) >= limit:
            break
    return ips


async def enrich_ips(
    db: DBSession,
    ips: Iterable[str],
    *,
    service: IPEnrichmentService,
) -> dict[str, int]:
    attempted = 0
    enriched = 0
    failed = 0

    for ip in ips:
        attempted += 1
        try:
            raw = await service.enrich(ip)
        except Exception as exc:
            logger.warning("Geo enrichment failed for %s: %s", ip, exc)
            raw = {"ip": ip, "country_name": "unknown", "enriched_at": datetime.utcnow()}
            failed += 1

        payload = normalize_enrichment_payload(ip, raw)
        try:
            upsert_ip_intel(db, payload)
            db.commit()
            enriched += 1
        except Exception:
            db.rollback()
            failed += 1
            logger.exception("Failed to store geo enrichment for %s", ip)

    return {"attempted": attempted, "stored": enriched, "failed": failed}
