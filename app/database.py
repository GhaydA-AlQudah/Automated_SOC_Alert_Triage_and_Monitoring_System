# app/database.py
"""
Async PostgreSQL Database Layer
================================

This module provides a lightweight, reusable async wrapper around `psycopg`
(v3) for executing SQL queries against the SOC Agent's PostgreSQL instance.

Design notes:
- The actual TCP connection is NOT opened in `__init__`. Async I/O can only
  happen inside a running event loop, so connection establishment is
  deferred to `connect()`, which is called lazily on first use.
- Autocommit is disabled by default, so every write must be explicitly
  committed via the `commit=True` flag on `execute()`. This keeps
  transaction boundaries explicit and predictable.
- On any query failure, the current transaction is rolled back to avoid
  leaving the connection in a broken/half-committed state.
"""

import os
from typing import Optional, Any, List, Union

import psycopg  # psycopg v3 — required for native async/await support
from dotenv import load_dotenv

from logger import logger

# Load DB_HOST / DB_NAME / DB_USER / DB_PASS / DB_PORT from the .env file
load_dotenv()

logger.info("[+] database.py: Initializing asynchronous database module...")


class Database:
    """
    Async utility class for managing a single PostgreSQL connection.

    Responsibilities:
    - Lazily establish an async connection to PostgreSQL on first query.
    - Execute parameterized SQL queries safely (no manual string
      interpolation of query params, protecting against SQL injection
      on the parameter side).
    - Manage transaction commit/rollback per call.
    - Provide a graceful shutdown path via `close()`.

    Usage:
        db = Database()
        rows = await db.execute("SELECT * FROM alerts WHERE alert_id = %s",
                                 params=(alert_id,), fetch=True, commit=False)
    """

    def __init__(self):
        """
        Prepare the connection parameters (as a libpq-style connection
        string) from environment variables.

        NOTE: This does NOT open a network connection. In an async
        architecture, connecting requires `await`, which is only valid
        inside an async method — hence `connect()` exists separately and
        is invoked on-demand by `execute()`.
        """
        self.conn: Optional[psycopg.AsyncConnection] = None

        # Build the libpq connection string from environment variables.
        # DB_PORT defaults to PostgreSQL's standard port (5432) if unset.
        self.conn_info = (
            f"host={os.getenv('DB_HOST')} "
            f"dbname={os.getenv('DB_NAME')} "
            f"user={os.getenv('DB_USER')} "
            f"password={os.getenv('DB_PASS')} "
            f"port={os.getenv('DB_PORT', '5432')}"
        )

    async def connect(self) -> None:
        """
        Establish the asynchronous connection to the PostgreSQL server.

        Autocommit is explicitly disabled so that every write operation
        must go through an explicit `commit()` call inside `execute()`.
        This gives callers full control over transaction boundaries.

        Raises:
            ConnectionError: If the async connection attempt fails for
                any reason (network issue, bad credentials, DB down, etc).
        """
        try:
            self.conn = await psycopg.AsyncConnection.connect(self.conn_info)

            # Disable autocommit -> every write requires an explicit commit.
            await self.conn.set_autocommit(False)

            logger.info("[+] Database: Asynchronous connection established successfully.")

        except Exception as e:
            logger.error(f"[-] Database: Critical Async Connection Error: {e}")
            raise ConnectionError(f"Could not connect to the database asynchronously: {e}")

    async def execute(
        self,
        query: str,
        params: Optional[Union[tuple, list]] = None,
        fetch: bool = False,
        commit: bool = True
    ) -> Optional[List[Any]]:
        """
        Execute a SQL query asynchronously, with safe parameter binding.

        Args:
            query: The SQL statement to execute. Use `%s` placeholders
                for any dynamic values — never interpolate user input
                directly into the query string.
            params: Positional parameters to bind to the query's `%s`
                placeholders, if any.
            fetch: If True, fetch and return all resulting rows
                (use for SELECT statements).
            commit: If True, commit the transaction after execution
                (use for INSERT/UPDATE/DELETE statements). Set to False
                for read-only SELECT queries to avoid unnecessary commits.

        Returns:
            A list of rows if `fetch=True`, otherwise `None`.

        Raises:
            Exception: Re-raises any exception encountered during query
                execution, after safely rolling back the transaction.
        """
        # Lazily (re)establish the connection if it doesn't exist yet,
        # or if a previous connection was closed/dropped.
        if not self.conn or self.conn.closed:
            await self.connect()

        result = None
        try:
            # Async context manager: the cursor is automatically closed
            # once the `async with` block exits, even on error.
            async with self.conn.cursor() as cur:
                # Non-blocking execution — the event loop remains free
                # to handle other coroutines while awaiting the network I/O.
                await cur.execute(query, params)

                if fetch:
                    result = await cur.fetchall()

                if commit:
                    await self.conn.commit()

                logger.debug(f"Database: Async query executed successfully: {query[:60]}...")
                return result

        except Exception as e:
            # Roll back to avoid leaving the connection in a broken/
            # partially-committed transactional state after a failure.
            if self.conn and not self.conn.closed:
                await self.conn.rollback()

            logger.error(f"[-] Database: Async Execution Error during query '{query[:60]}': {e}")
            raise e

    async def close(self) -> None:
        """
        Gracefully close the database connection, if one is open.

        Safe to call multiple times or on an already-closed connection —
        it simply becomes a no-op in that case.
        """
        try:
            if self.conn and not self.conn.closed:
                await self.conn.close()
                logger.info("[+] Database: Async Connection closed successfully.")

        except Exception as e:
            logger.error(f"[-] Database: Error while closing async connection: {e}")


logger.info("[@] database.py: Async Module ready for operations.")