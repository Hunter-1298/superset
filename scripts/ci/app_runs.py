#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""`app-runs`: prove the exact `ci` image digest runs end-to-end with Postgres + Redis.

Starts scripts/ci/app_runs/docker-compose.yml around ``$SUPERSET_IMAGE`` (an
immutable ``repo@sha256:...`` reference that must already be pulled) and
verifies, through the public REST API only:

1. migrations   ``superset db upgrade`` succeeds and the DB is at the migration head
2. health       the default entrypoint answers ``/health`` = 200 ``OK`` within 120 s
3. login        a DB login returns a JWT; ``/api/v1/me/`` answers 200 for it
4. dashboards   a database, dataset, chart and dashboard can be created and listed
5. chart data   ``/api/v1/chart/data`` returns exactly the 10 seeded rows
6. SQL Lab      synchronous ``SELECT 1 AS ok`` succeeds; an asynchronous query is
                executed by the Celery worker and its result is stored in Redis
7. CSV export   chart-data CSV and SQL Lab CSV export return well-formed CSV
8. worker       ``celery inspect ping`` answers from the worker container

Every HTTP response, container log and a machine-readable ``app-runs.json`` are
written to ``--out`` so the run can be attached as evidence. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import http.cookiejar
import io
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
COMPOSE_FILE = HERE / "app_runs" / "docker-compose.yml"
SEED_TABLE = "app_runs_metrics"
SEED_ROWS = 10


class CheckFailedError(Exception):
    """A verified behaviour did not hold."""


def redact(cmd: list[str]) -> list[str]:
    """Hide the value following any ``--password`` flag before echoing a command."""
    redacted = list(cmd)
    for i, arg in enumerate(redacted[:-1]):
        if arg == "--password":
            redacted[i + 1] = "***"
    return redacted


@dataclass
class Report:
    image_ref: str
    checks: dict[str, str] = field(default_factory=dict)
    failed_step: str | None = None
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_ref": self.image_ref,
            "passed": self.passed,
            "failed_step": self.failed_step,
            "checks": self.checks,
        }


class Compose:
    """Thin wrapper over `docker compose` for one isolated project."""

    def __init__(
        self, docker: str, project: str, env: dict[str, str], out: Path
    ) -> None:
        self.docker = docker
        self.project = project
        self.env = env
        self.out = out

    def _cmd(self, *args: str) -> list[str]:
        return [
            self.docker,
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "-p",
            self.project,
            *args,
        ]

    def run(self, *args: str, check: bool = True, log: str | None = None) -> str:
        cmd = self._cmd(*args)
        print("+", " ".join(shlex.quote(c) for c in redact(cmd)), flush=True)
        proc = subprocess.run(  # noqa: S603
            cmd, env=self.env, capture_output=True, text=True, check=False
        )
        output = proc.stdout + proc.stderr
        if log:
            (self.out / log).write_text(output)
        if check and proc.returncode != 0:
            print(output[-4000:], file=sys.stderr)
            raise CheckFailedError(f"{' '.join(args[:3])} exited {proc.returncode}")
        return output

    def exec_(self, service: str, *args: str, check: bool = True) -> str:
        return self.run("exec", "-T", service, *args, check=check)

    def one_shot(self, *args: str, log: str) -> str:
        return self.run("run", "--rm", "--no-deps", "superset-init", *args, log=log)

    def port(self, service: str, container_port: int) -> int:
        mapping = self.run("port", service, str(container_port)).strip().splitlines()[0]
        return int(mapping.rsplit(":", 1)[1])

    def dump_logs(self) -> None:
        for service in ("postgres", "redis", "superset", "worker"):
            self.run("logs", "--no-color", service, check=False, log=f"{service}.log")

    def down(self) -> None:
        self.run(
            "down", "--volumes", "--remove-orphans", "--timeout", "20", check=False
        )


class Api:
    """Cookie-aware JSON client for the Superset REST API (Bearer JWT + CSRF)."""

    def __init__(self, base: str, out: Path) -> None:
        if not base.startswith("http://"):
            raise CheckFailedError(
                f"API base must be a local http:// URL, got {base!r}"
            )
        self.base = base.rstrip("/")
        self.out = out
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.token: str | None = None
        self.csrf: str | None = None
        self._n = 0

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        name: str,
        expect: int | tuple[int, ...] = 200,
        auth: bool = True,
        redact_keys: frozenset[str] = frozenset(),
    ) -> tuple[int, bytes, dict[str, str]]:
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)  # noqa: S310
        req.add_header("Accept", "application/json, text/csv")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if auth and self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if self.csrf and method not in {"GET", "HEAD", "OPTIONS"}:
            req.add_header("X-CSRFToken", self.csrf)
            req.add_header("Referer", self.base + "/")
        try:
            with self.opener.open(req, timeout=60) as resp:  # noqa: S310 - scheme checked in __init__
                status, raw, headers = resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            status, raw, headers = exc.code, exc.read(), dict(exc.headers)
        self._n += 1
        ext = "csv" if "text/csv" in headers.get("Content-Type", "") else "json"
        saved = raw
        if redact_keys and ext == "json":
            try:
                doc = json.loads(raw)
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                saved = json.dumps(
                    {
                        k: ("<redacted>" if k in redact_keys else v)
                        for k, v in doc.items()
                    }
                ).encode()
        (self.out / f"http-{self._n:02d}-{name}.{ext}").write_bytes(saved)
        expected = expect if isinstance(expect, tuple) else (expect,)
        if status not in expected:
            raise CheckFailedError(
                f"{method} {path} -> {status}, expected {expected}: {raw[:800]!r}"
            )
        return status, raw, headers

    def json(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        name: str,
        expect: int | tuple[int, ...] = 200,
    ) -> Any:
        _, raw, _ = self.request(method, path, body, name=name, expect=expect)
        return json.loads(raw)

    def login(self, username: str, password: str) -> None:
        _, raw, _ = self.request(
            "POST",
            "/api/v1/security/login",
            {
                "username": username,
                "password": password,
                "provider": "db",
                "refresh": True,
            },
            name="login",
            redact_keys=frozenset({"access_token", "refresh_token"}),
        )
        payload = json.loads(raw)
        self.token = payload["access_token"]
        if not self.token:
            raise CheckFailedError("login returned no access_token")
        self.csrf = self.json("GET", "/api/v1/security/csrf_token/", name="csrf")[
            "result"
        ]


def wait_for_health(api: Api, timeout: float) -> float:
    start = time.monotonic()
    last: str = "no response"
    while time.monotonic() - start < timeout:
        try:
            status, raw, _ = api.request(
                "GET", "/health", name="health", expect=(200, 500, 502, 503), auth=False
            )
            last = f"{status} {raw[:40]!r}"
            if status == 200 and raw.strip() == b"OK":
                return time.monotonic() - start
        except (urllib.error.URLError, OSError, CheckFailedError) as exc:
            last = str(exc)
        time.sleep(2)
    raise CheckFailedError(
        f"/health did not answer 200 OK within {timeout:.0f}s (last: {last})"
    )


def sqllab_execute(
    api: Api, database_id: int, sql: str, *, run_async: bool, name: str
) -> Any:
    client_id = secrets.token_hex(5)
    return api.json(
        "POST",
        "/api/v1/sqllab/execute/",
        {
            "database_id": database_id,
            "sql": sql,
            "schema": "public",
            "runAsync": run_async,
            "client_id": client_id,
            "sql_editor_id": "app-runs",
            "tab": "app-runs",
            "select_as_cta": False,
        },
        name=name,
        expect=(200, 202),
    )


def wait_for_query(api: Api, query_id: int, timeout: float = 120) -> dict[str, Any]:
    start = time.monotonic()
    state = "unknown"
    while time.monotonic() - start < timeout:
        result = api.json("GET", f"/api/v1/query/{query_id}", name="query-status")[
            "result"
        ]
        state = result["status"]
        if state == "success":
            return result
        if state in {"failed", "stopped", "timed_out"}:
            raise CheckFailedError(
                f"async query {query_id} ended in state {state}: "
                f"{result.get('error_message')}"
            )
        time.sleep(2)
    raise CheckFailedError(f"async query {query_id} still {state} after {timeout:.0f}s")


def parse_csv(raw: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))


@dataclass
class Run:
    """Mutable state shared by the ordered verification steps."""

    compose: Compose
    out: Path
    report: Report
    admin_user: str
    admin_password: str
    db_password: str
    health_timeout: float
    api: Api | None = None
    database_id: int = 0
    dataset_id: int = 0
    chart_id: int = 0
    dashboard_id: int = 0
    sync_client_id: str = ""

    def record(self, name: str, value: str) -> None:
        """Store one human-readable check result and echo it."""
        self.report.checks[name] = value
        print(f"[{name}] {value}", flush=True)

    def client(self) -> Api:
        """Return the API client once the app container is up."""
        if self.api is None:
            raise CheckFailedError("API client used before the app was started")
        return self.api

    def query_context(self) -> dict[str, Any]:
        """Chart-data query context that selects every seeded row."""
        return {
            "datasource": {"id": self.dataset_id, "type": "table"},
            "force": True,
            "queries": [
                {
                    "columns": ["id", "label", "value"],
                    "row_limit": 100,
                    "orderby": [["id", True]],
                }
            ],
            "result_format": "json",
            "result_type": "full",
        }


def step_deps(run: Run) -> None:
    """Start Postgres and Redis and wait for their health checks."""
    run.compose.run(
        "up", "-d", "--wait", "postgres", "redis", log="compose-up-deps.log"
    )


def step_migrations(run: Run) -> None:
    """Upgrade the metadata DB and require it to sit at the migration head."""
    run.compose.one_shot("superset", "db", "upgrade", log="db-upgrade.log")
    current = run.compose.one_shot("superset", "db", "current", log="db-current.log")
    head_lines = [line for line in current.splitlines() if "(head)" in line]
    if not head_lines:
        raise CheckFailedError(
            "metadata DB is not at the migration head after db upgrade"
        )
    run.record("migrations", head_lines[-1].strip())


def step_init(run: Run) -> None:
    """Create the admin user and run `superset init`."""
    run.compose.one_shot(
        "superset",
        "fab",
        "create-admin",
        "--username",
        run.admin_user,
        "--firstname",
        "App",
        "--lastname",
        "Runs",
        "--email",
        "app-runs@example.invalid",
        "--password",
        run.admin_password,
        log="create-admin.log",
    )
    run.compose.one_shot("superset", "init", log="init.log")
    run.record("init", "ok")


def step_app_up(run: Run) -> None:
    """Start the web and Celery worker containers from the exact digest."""
    run.compose.run(
        "up", "-d", "--no-deps", "superset", "worker", log="compose-up-app.log"
    )
    port = run.compose.port("superset", 8088)
    run.api = Api(f"http://127.0.0.1:{port}", run.out)


def step_health(run: Run) -> None:
    """`/health` must answer 200 OK within the configured timeout."""
    elapsed = wait_for_health(run.client(), run.health_timeout)
    run.record("health", f"200 OK after {elapsed:.0f}s")


def step_login(run: Run) -> None:
    """A DB login yields a JWT accepted by /api/v1/me/; a wrong password is rejected."""
    api = run.client()
    api.login(run.admin_user, run.admin_password)
    me = api.json("GET", "/api/v1/me/", name="me")["result"]
    if me["username"] != run.admin_user:
        raise CheckFailedError(f"/api/v1/me/ is {me['username']!r}")
    api.request(
        "POST",
        "/api/v1/security/login",
        {
            "username": run.admin_user,
            "password": "wrong-" + run.admin_password,
            "provider": "db",
        },
        name="login-invalid",
        expect=401,
        auth=False,
    )
    run.record(
        "login", f"JWT issued; /api/v1/me/ -> {me['username']}; invalid login -> 401"
    )


def step_database(run: Run) -> None:
    """Register the Postgres service as a Superset database."""
    api = run.client()
    db = api.json(
        "POST",
        "/api/v1/database/",
        {
            "database_name": "app-runs-postgres",
            "sqlalchemy_uri": (
                f"postgresql+psycopg2://superset:{run.db_password}@postgres:5432/superset"
            ),
            "expose_in_sqllab": True,
            "allow_run_async": True,
            "allow_dml": True,
            "allow_ctas": False,
            "allow_cvas": False,
        },
        name="database-create",
        expect=201,
    )
    run.database_id = int(db["id"])
    conn = api.json(
        "GET",
        f"/api/v1/database/{run.database_id}/connection",
        name="database-connection",
    )["result"]
    backend = conn.get("backend") or conn.get("sqlalchemy_uri", "").split(":", 1)[0]
    if not str(backend).startswith("postgresql"):
        raise CheckFailedError(
            f"connection backend is {backend!r}, expected postgresql"
        )
    run.record("database", f"id={run.database_id} backend={backend}")


def step_seed(run: Run) -> None:
    """Create the fixture table through SQL Lab DML."""
    seed = sqllab_execute(
        run.client(),
        run.database_id,
        f"CREATE TABLE {SEED_TABLE} AS "  # noqa: S608 - constant identifier, throwaway DB
        f"SELECT g AS id, 'row-' || g AS label, g * 1.5 AS value "
        f"FROM generate_series(1, {SEED_ROWS}) AS g",
        run_async=False,
        name="sqllab-seed",
    )
    if seed.get("status") != "success":
        raise CheckFailedError(f"seed statement status {seed.get('status')!r}: {seed}")


def step_dashboards(run: Run) -> None:
    """Create a dataset, chart and dashboard; the dashboard must list its chart."""
    api = run.client()
    dataset = api.json(
        "POST",
        "/api/v1/dataset/",
        {"database": run.database_id, "schema": "public", "table_name": SEED_TABLE},
        name="dataset-create",
        expect=201,
    )
    run.dataset_id = int(dataset["id"])
    chart = api.json(
        "POST",
        "/api/v1/chart/",
        {
            "slice_name": "app-runs table",
            "viz_type": "table",
            "datasource_id": run.dataset_id,
            "datasource_type": "table",
            "params": json.dumps(
                {
                    "datasource": f"{run.dataset_id}__table",
                    "viz_type": "table",
                    "query_mode": "raw",
                    "all_columns": ["id", "label", "value"],
                    "order_by_cols": [],
                    "row_limit": 100,
                }
            ),
        },
        name="chart-create",
        expect=201,
    )
    run.chart_id = int(chart["id"])
    dashboard = api.json(
        "POST",
        "/api/v1/dashboard/",
        {"dashboard_title": "app-runs", "slug": "app-runs", "published": True},
        name="dashboard-create",
        expect=201,
    )
    run.dashboard_id = int(dashboard["id"])
    api.json(
        "PUT",
        f"/api/v1/chart/{run.chart_id}",
        {"dashboards": [run.dashboard_id]},
        name="chart-attach",
    )
    listing = api.json("GET", "/api/v1/dashboard/", name="dashboard-list")
    slugs = sorted(d["slug"] for d in listing["result"] if d.get("slug"))
    if "app-runs" not in slugs:
        raise CheckFailedError(f"dashboard list lacks slug app-runs: {slugs}")
    charts_on_dash = api.json(
        "GET", f"/api/v1/dashboard/{run.dashboard_id}/charts", name="dashboard-charts"
    )
    if run.chart_id not in {c["id"] for c in charts_on_dash["result"]}:
        raise CheckFailedError(
            f"chart {run.chart_id} not on dashboard {run.dashboard_id}"
        )
    run.record(
        "dashboards",
        f"dataset={run.dataset_id} chart={run.chart_id} "
        f"dashboard={run.dashboard_id} listed=yes",
    )


def step_chart_data(run: Run) -> None:
    """`/api/v1/chart/data` returns exactly the seeded rows."""
    data = run.client().json(
        "POST", "/api/v1/chart/data", run.query_context(), name="chart-data"
    )
    result = data["result"][0]
    rows = result["data"]
    if len(rows) != SEED_ROWS or result["status"] != "success":
        raise CheckFailedError(
            f"chart data returned {len(rows)} rows / status {result.get('status')}"
        )
    run.record("chart_data", f"{len(rows)} rows, status={result['status']}")


def step_csv_chart(run: Run) -> None:
    """Chart-data CSV export is well-formed and complete."""
    _, csv_raw, headers = run.client().request(
        "POST",
        "/api/v1/chart/data",
        {**run.query_context(), "result_format": "csv"},
        name="chart-data-csv",
    )
    if "text/csv" not in headers.get("Content-Type", ""):
        raise CheckFailedError(
            f"chart CSV content-type {headers.get('Content-Type')!r}"
        )
    csv_rows = parse_csv(csv_raw)
    header = list(csv_rows[0]) if csv_rows else []
    if len(csv_rows) != SEED_ROWS or set(header) != {"id", "label", "value"}:
        raise CheckFailedError(
            f"chart CSV has {len(csv_rows)} rows with columns {header}"
        )
    run.record(
        "csv_export_chart", f"text/csv, {len(csv_rows)} rows, header={sorted(header)}"
    )


def step_sqllab_sync(run: Run) -> None:
    """A synchronous SQL Lab query returns its rows inline."""
    sync = sqllab_execute(
        run.client(),
        run.database_id,
        "SELECT 1 AS ok",
        run_async=False,
        name="sqllab-sync",
    )
    if sync.get("status") != "success" or sync.get("data") != [{"ok": 1}]:
        raise CheckFailedError(
            f"sync SQL Lab returned {sync.get('status')!r} {sync.get('data')!r}"
        )
    run.sync_client_id = str(sync["query"]["id"])  # SQL Lab's `id` is the client id
    run.record("sqllab_sync", "SELECT 1 AS ok -> [{'ok': 1}]")


def step_csv_sqllab(run: Run) -> None:
    """SQL Lab CSV export of the synchronous query is well-formed."""
    _, sql_csv, headers = run.client().request(
        "GET", f"/api/v1/sqllab/export/{run.sync_client_id}/", name="sqllab-csv"
    )
    if "text/csv" not in headers.get("Content-Type", ""):
        raise CheckFailedError(
            f"SQL Lab CSV content-type {headers.get('Content-Type')!r}"
        )
    sql_rows = parse_csv(sql_csv)
    if sql_rows != [{"ok": "1"}]:
        raise CheckFailedError(f"SQL Lab CSV rows {sql_rows!r}")
    run.record("csv_export_sqllab", "text/csv, 1 row, header=['ok']")


def step_sqllab_async(run: Run) -> None:
    """An asynchronous SQL Lab query runs on the Celery worker with results in Redis."""
    api = run.client()
    async_resp = sqllab_execute(
        api,
        run.database_id,
        f"SELECT count(*) AS n FROM {SEED_TABLE}",  # noqa: S608 - constant identifier
        run_async=True,
        name="sqllab-async",
    )
    query_id = int(async_resp["query"]["queryId"])
    finished = wait_for_query(api, query_id)
    results_key = finished.get("results_key") or finished.get("resultsKey")
    if not results_key:
        raise CheckFailedError(f"async query {query_id} finished without a results key")
    results = api.json(
        "GET",
        "/api/v1/sqllab/results/?"
        + urllib.parse.urlencode({"q": f"(key:'{results_key}')"}),
        name="sqllab-results",
    )
    if results.get("data") != [{"n": SEED_ROWS}]:
        raise CheckFailedError(f"async results {results.get('data')!r}")
    redis_keys = run.compose.exec_(
        "redis", "redis-cli", "-n", "1", "--scan", "--pattern", "superset_results*"
    ).split()
    if not redis_keys:
        raise CheckFailedError(
            "no superset_results* key in Redis db 1 after the async query"
        )
    run.record(
        "sqllab_async",
        f"query {query_id} ran on worker; {len(redis_keys)} result key(s) in Redis",
    )


def step_worker(run: Run) -> None:
    """`celery inspect ping` answers from the worker container."""
    ping = run.compose.exec_(
        "worker",
        "celery",
        "--app=superset.tasks.celery_app:app",
        "inspect",
        "ping",
        "--timeout",
        "15",
    )
    if "pong" not in ping:
        raise CheckFailedError(
            f"celery inspect ping did not answer pong: {ping[-500:]}"
        )
    run.record(
        "worker",
        next((line.strip() for line in ping.splitlines() if "pong" in line), "pong"),
    )


STEPS: tuple[tuple[str, Callable[[Run], None]], ...] = (
    ("compose up (postgres, redis)", step_deps),
    ("migrations", step_migrations),
    ("create-admin + init", step_init),
    ("compose up (superset, worker)", step_app_up),
    ("health", step_health),
    ("login", step_login),
    ("database", step_database),
    ("seed table (SQL Lab DML)", step_seed),
    ("dataset + chart + dashboard", step_dashboards),
    ("chart data", step_chart_data),
    ("CSV export (chart data)", step_csv_chart),
    ("SQL Lab (sync)", step_sqllab_sync),
    ("CSV export (SQL Lab)", step_csv_sqllab),
    ("SQL Lab (async via Celery, results in Redis)", step_sqllab_async),
    ("worker ping", step_worker),
)


def image_present(docker: str, image_ref: str) -> bool:
    """True when a local image's RepoDigests include ``image_ref``."""
    present = subprocess.run(  # noqa: S603
        [
            docker,
            "image",
            "inspect",
            "--format",
            '{{join .RepoDigests "\\n"}}',
            image_ref,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return present.returncode == 0 and image_ref in present.stdout.split()


def main() -> int:
    """Parse arguments, run every step in order and write ``app-runs.json``."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", required=True, type=Path, help="evidence directory")
    parser.add_argument(
        "--image",
        default=os.environ.get("SUPERSET_IMAGE"),
        help="repo@sha256:... (default $SUPERSET_IMAGE)",
    )
    parser.add_argument("--health-timeout", type=float, default=120.0)
    parser.add_argument(
        "--keep", action="store_true", help="leave the compose stack running on exit"
    )
    args = parser.parse_args()

    image_ref = args.image or ""
    if "@sha256:" not in image_ref:
        print(f"::error::SUPERSET_IMAGE must be repo@sha256:..., got {image_ref!r}")
        return 2
    docker = shutil.which("docker")
    if docker is None:
        print("::error::docker not found on PATH")
        return 2
    if not image_present(docker, image_ref):
        print(
            f"::error::{image_ref} not present locally; run pull_exact_image.sh first"
        )
        return 2

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    db_password = secrets.token_urlsafe(18)
    env = {
        **os.environ,
        "SUPERSET_IMAGE": image_ref,
        "SUPERSET_SECRET_KEY": secrets.token_urlsafe(42),
        "DATABASE_PASSWORD": db_password,
        "APP_RUNS_PORT": os.environ.get("APP_RUNS_PORT", "0"),
    }
    compose = Compose(docker, f"apprun{secrets.token_hex(3)}", env, out)
    run = Run(
        compose=compose,
        out=out,
        report=Report(image_ref=image_ref),
        admin_user="admin",
        admin_password=secrets.token_urlsafe(18),
        db_password=db_password,
        health_timeout=args.health_timeout,
    )
    step = "setup"
    try:
        for name, fn in STEPS:
            step = name
            fn(run)
        run.report.passed = True
        print(f"app-runs passed for {image_ref}", flush=True)
        return 0
    except (
        CheckFailedError,
        KeyError,
        ValueError,
        TypeError,
        IndexError,
        OSError,
    ) as exc:
        run.report.failed_step = step
        print(
            f"::error::app-runs failed at step '{step}': {exc!r}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    finally:
        compose.dump_logs()
        (out / "app-runs.json").write_text(
            json.dumps(run.report.to_dict(), indent=2, sort_keys=True) + "\n"
        )
        if not args.keep:
            compose.down()


if __name__ == "__main__":
    sys.exit(main())
