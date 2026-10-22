"""SQLite-backed multi-tenant synthetic data store for the mock upstream backend.

SECURITY ARCHITECTURE NOTE:
- Uses strictly parameterized SQL queries. Never concatenates strings or executes raw user SQL.
- Enforces tenant scoping in data-access operations.
- Separates tenant-alpha and tenant-beta data for BOLA / cross-tenant isolation testing.
"""
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from src.schemas.order import OrderCreate, OrderRecord


def get_default_db_path() -> Path:
    """Resolve database path from environment variable or project root."""
    env_path = os.getenv("UPSTREAM_DB_PATH")
    if env_path:
        return Path(env_path)
    project_root = Path(__file__).resolve().parent.parent.parent
    return project_root / "synthetic_upstream.db"


class ClosingConnection(sqlite3.Connection):
    """Custom SQLite connection that commits and closes itself when used in a with block."""
    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        try:
            super().__exit__(exc_type, exc_val, exc_tb)  # type: ignore[arg-type]
        finally:
            self.close()


class OrderStore:
    """SQLite-backed repository for multi-tenant synthetic orders."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or get_default_db_path()
        self.reset()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a connection with Row factory enabled and auto-closing with context."""
        conn = sqlite3.connect(self.db_path, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        return conn

    def reset(self) -> None:
        """Recreate the orders table and seed with predictable multi-tenant test records."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS orders")
            cursor.execute(
                """
                CREATE TABLE orders (
                    order_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    customer_name TEXT NOT NULL,
                    item TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    total_price REAL NOT NULL,
                    notes TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX idx_orders_tenant ON orders (tenant_id, order_id)")

            # Predictable multi-tenant seed records
            seeds = [
                # Tenant Alpha Records
                (
                    "ORD-1001",
                    "tenant-alpha",
                    "Alice Smith",
                    "Security Audit Handbook",
                    1,
                    49.99,
                    "Priority customer delivery",
                    "COMPLETED",
                    "2026-01-15T10:00:00Z",
                ),
                (
                    "ORD-1002",
                    "tenant-alpha",
                    "Bob Jones",
                    "Cloud Telemetry Gateway",
                    2,
                    199.50,
                    "Standard commercial shipping",
                    "PROCESSING",
                    "2026-01-16T14:30:00Z",
                ),
                # Tenant Beta Records
                (
                    "ORD-1003",
                    "tenant-beta",
                    "Charlie Brown",
                    "Synthetic Test Widget",
                    5,
                    25.00,
                    "Lab evaluation sample",
                    "PENDING",
                    "2026-01-17T09:15:00Z",
                ),
                (
                    "ORD-2001",
                    "tenant-beta",
                    "Diana Prince",
                    "Threat Modeling Workshop Ticket",
                    2,
                    450.00,
                    "Urgent registration",
                    "COMPLETED",
                    "2026-01-18T11:20:00Z",
                ),
            ]

            cursor.executemany(
                """
                INSERT INTO orders (
                    order_id, tenant_id, customer_name, item, quantity, total_price, notes, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                seeds,
            )
            conn.commit()
        finally:
            conn.close()

    def get_order(self, order_id: str, tenant_id: str) -> Optional[OrderRecord]:
        """Retrieve an order strictly matching both order_id and tenant_id using parameterized SQL."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT order_id, tenant_id, customer_name, item, quantity, total_price, notes, status, created_at
                FROM orders
                WHERE order_id = ? AND tenant_id = ?
                """,
                (order_id, tenant_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return OrderRecord(
                order_id=row["order_id"],
                tenant_id=row["tenant_id"],
                customer_name=row["customer_name"],
                item=row["item"],
                quantity=row["quantity"],
                total_price=row["total_price"],
                notes=row["notes"],
                status=row["status"],
                created_at=row["created_at"],
            )
        finally:
            conn.close()

    def get_order_any_tenant(self, order_id: str) -> Optional[OrderRecord]:
        """Check if an order exists across any tenant (used internally for BOLA discrimination)."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT order_id, tenant_id, customer_name, item, quantity, total_price, notes, status, created_at
                FROM orders
                WHERE order_id = ?
                """,
                (order_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return OrderRecord(
                order_id=row["order_id"],
                tenant_id=row["tenant_id"],
                customer_name=row["customer_name"],
                item=row["item"],
                quantity=row["quantity"],
                total_price=row["total_price"],
                notes=row["notes"],
                status=row["status"],
                created_at=row["created_at"],
            )
        finally:
            conn.close()

    def create_order(self, data: OrderCreate, tenant_id: str) -> OrderRecord:
        """Create a new order strictly bound to the authenticated tenant_id using parameterized SQL."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Find next available numeric ID
            cursor.execute("SELECT COUNT(*) FROM orders")
            count = cursor.fetchone()[0]
            new_id = f"ORD-{3000 + count + 1}"
            now_iso = datetime.now(timezone.utc).isoformat()

            cursor.execute(
                """
                INSERT INTO orders (
                    order_id, tenant_id, customer_name, item, quantity, total_price, notes, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id,
                    tenant_id,
                    data.customer_name,
                    data.item,
                    data.quantity,
                    data.total_price,
                    data.notes,
                    "PENDING",
                    now_iso,
                ),
            )
            conn.commit()

            return OrderRecord(
                order_id=new_id,
                tenant_id=tenant_id,
                customer_name=data.customer_name,
                item=data.item,
                quantity=data.quantity,
                total_price=data.total_price,
                notes=data.notes,
                status="PENDING",
                created_at=now_iso,
            )
        finally:
            conn.close()


# Global singleton instance for the mock upstream process
order_store = OrderStore()
