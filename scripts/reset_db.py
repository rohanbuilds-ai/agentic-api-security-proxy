"""Utility script to reset and seed the synthetic multi-tenant SQLite database.

Usage:
  python scripts/reset_db.py
"""
import sys
from src.upstream.store import order_store


def main() -> None:
    print(f"Resetting synthetic SQLite database at: {order_store.db_path} ...")
    order_store.reset()
    print("Database reset successfully.")
    print("Seeded predictable records:")
    print(" - ORD-1001 (tenant-alpha, Alice Smith, COMPLETED)")
    print(" - ORD-1002 (tenant-alpha, Bob Jones, PROCESSING)")
    print(" - ORD-1003 (tenant-beta, Charlie Brown, PENDING)")
    print(" - ORD-2001 (tenant-beta, Diana Prince, COMPLETED)")


if __name__ == "__main__":
    main()
