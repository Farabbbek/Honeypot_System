import ipaddress
import logging
import os
from datetime import datetime
from typing import Any

import httpx

try:
    import geoip2.database
except ImportError:  # pragma: no cover
    geoip2 = None

logger = logging.getLogger(__name__)


class IPEnrichmentService:
    def __init__(self) -> None:
        self.geoip_city_db = os.getenv("GEOIP_CITY_DB", "/app/geoip/GeoLite2-City.mmdb")
        self.geoip_asn_db = os.getenv("GEOIP_ASN_DB", "/app/geoip/GeoLite2-ASN.mmdb")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.ip_api_url = os.getenv("IP_API_URL", "http://ip-api.com/json/{ip}")

    async def enrich(self, ip: str) -> dict[str, Any]:
        if self.is_private_ip(ip):
            data = {
                "ip": ip,
                "country_code": "LAN",
                "country_name": "Private Network",
                "city": "Local",
                "latitude": None,
                "longitude": None,
                "asn": None,
                "org_name": "Local Network",
                "abuse_confidence_score": None,
                "total_reports": 0,
                "last_reported_at": None,
                "is_tor": False,
                "is_vpn": False,
            }
            data["enriched_at"] = datetime.utcnow()
            return data

        data = {"ip": ip}
        geoip_data = self.lookup_geoip(ip)
        if not self.has_usable_geo_data(geoip_data):
            fallback_data = await self.lookup_ip_api(ip)
            geoip_data = self.merge_missing_geo_fields(geoip_data, fallback_data)
        data.update(geoip_data)
        data.update(await self.lookup_abuseipdb(ip))
        data["enriched_at"] = datetime.utcnow()
        return data

    def lookup_geoip(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "country_code": None,
            "country_name": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "org_name": None,
        }
        if geoip2 is None:
            return result

        if os.path.exists(self.geoip_city_db):
            try:
                with geoip2.database.Reader(self.geoip_city_db) as reader:
                    response = reader.city(ip)
                    result.update(
                        {
                            "country_code": response.country.iso_code,
                            "country_name": response.country.name,
                            "city": response.city.name,
                            "latitude": response.location.latitude,
                            "longitude": response.location.longitude,
                        }
                    )
            except Exception as exc:
                logger.info("GeoIP city lookup did not return data for %s: %s", ip, exc)

        if os.path.exists(self.geoip_asn_db):
            try:
                with geoip2.database.Reader(self.geoip_asn_db) as reader:
                    response = reader.asn(ip)
                    result.update({"asn": str(response.autonomous_system_number), "org_name": response.autonomous_system_organization})
            except Exception as exc:
                logger.info("GeoIP ASN lookup did not return data for %s: %s", ip, exc)

        return result

    async def lookup_ip_api(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "country_code": None,
            "country_name": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "org_name": None,
        }
        try:
            url = self.ip_api_url.format(ip=ip)
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            logger.info("ip-api.com lookup failed for %s: %s", ip, exc)
            return result

        if payload.get("status") != "success":
            logger.info("ip-api.com returned no geo data for %s: %s", ip, payload.get("message"))
            return result

        result.update(
            {
                "country_code": payload.get("countryCode"),
                "country_name": payload.get("country"),
                "city": payload.get("city"),
                "latitude": payload.get("lat"),
                "longitude": payload.get("lon"),
                "asn": self.parse_ip_api_asn(payload.get("as")),
                "org_name": payload.get("org"),
            }
        )
        return result

    def merge_missing_geo_fields(self, primary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
        merged = dict(primary)
        for key, value in fallback.items():
            if merged.get(key) in {None, ""} and value not in {None, ""}:
                merged[key] = value
        return merged

    def has_usable_coordinates(self, data: dict[str, Any]) -> bool:
        try:
            lat = float(data.get("latitude"))
            lng = float(data.get("longitude"))
        except (TypeError, ValueError):
            return False
        return lat != 0 and lng != 0 and -90 <= lat <= 90 and -180 <= lng <= 180

    def has_usable_geo_data(self, data: dict[str, Any]) -> bool:
        return bool(data.get("country_name")) and self.has_usable_coordinates(data)

    def parse_ip_api_asn(self, value: Any) -> str | None:
        if not value:
            return None
        first = str(value).split()[0]
        return first[2:] if first.upper().startswith("AS") else first

    async def lookup_abuseipdb(self, ip: str) -> dict[str, Any]:
        if not self.abuseipdb_key:
            return {
                "abuse_confidence_score": None,
                "total_reports": 0,
                "last_reported_at": None,
                "is_tor": False,
                "is_vpn": False,
            }

        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            response.raise_for_status()
            payload = response.json()["data"]

        return {
            "abuse_confidence_score": payload.get("abuseConfidenceScore"),
            "total_reports": payload.get("totalReports", 0),
            "last_reported_at": payload.get("lastReportedAt"),
            "is_tor": payload.get("isTor", False),
            "is_vpn": payload.get("isVpn", False),
        }

    def is_private_ip(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved
