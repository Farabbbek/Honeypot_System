import argparse
import asyncio
import logging
from datetime import timedelta

from database import SessionLocal
from geo_utils import enrich_ips, geo_session_counts, recent_ips_needing_geo
from ip_enrichment import IPEnrichmentService


async def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill GeoIP data for existing honeypot sessions.")
    parser.add_argument("--limit", type=int, default=1000, help="Maximum unique attacker IPs to enrich.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Retry all missing/unknown geo rows regardless of enriched_at age.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    with SessionLocal() as db:
        before = geo_session_counts(db)
        refresh_after = timedelta(0) if args.force else timedelta(hours=24)
        ips = recent_ips_needing_geo(
            db,
            limit=args.limit,
            refresh_after=refresh_after,
            force=args.force,
        )
        print(
            "Before: "
            f"total_sessions={before['total_sessions']} "
            f"sessions_with_country={before['sessions_with_country']} "
            f"sessions_with_valid_lat_lng={before['sessions_with_valid_lat_lng']}"
        )
        print(f"Unique attacker IPs needing geo backfill: {len(ips)}")

        result = await enrich_ips(db, ips, service=IPEnrichmentService())
        after = geo_session_counts(db)

        print(
            "Backfill: "
            f"attempted={result['attempted']} "
            f"stored={result['stored']} "
            f"failed={result['failed']}"
        )
        print(
            "After: "
            f"total_sessions={after['total_sessions']} "
            f"sessions_with_country={after['sessions_with_country']} "
            f"sessions_with_valid_lat_lng={after['sessions_with_valid_lat_lng']}"
        )


if __name__ == "__main__":
    asyncio.run(main())
