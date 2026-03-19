import asyncio
import html
import ipaddress
import platform
import re
import socket
import sqlite3
import statistics
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, Response


DB_PATH = Path("network_monitor_auto.db")
EXTERNAL_TARGETS_FILE = Path("external_targets.txt")
BLOCKED_TARGETS_FILE = Path("blocked_targets.txt")

PING_COUNT = 20
INTERVAL_SECONDS = 15 * 60
PING_TIMEOUT_MS = 1000

DISCOVERY_LIMIT = 254
DISCOVERY_CONCURRENCY = 64


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_group TEXT NOT NULL,
            expected_state TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            success INTEGER NOT NULL,
            packet_loss_pct REAL,
            min_latency_ms REAL,
            avg_latency_ms REAL,
            max_latency_ms REAL,
            jitter_ms REAL,
            probable_cause TEXT,
            policy_status TEXT NOT NULL,
            raw_output TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_results_target_checked_at
        ON results(target, checked_at DESC)
        """
    )

    conn.commit()
    conn.close()


def ensure_files_exist() -> None:
    if not EXTERNAL_TARGETS_FILE.exists():
        EXTERNAL_TARGETS_FILE.write_text("8.8.8.8\n1.1.1.1\n", encoding="utf-8")

    if not BLOCKED_TARGETS_FILE.exists():
        BLOCKED_TARGETS_FILE.write_text(
            "# Add IPs or hostnames that should be blocked by firewall\n",
            encoding="utf-8",
        )


def read_targets_file(path: Path) -> list[str]:
    values: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)

    seen = set()
    unique_values = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique_values.append(value)

    return unique_values


def infer_probable_cause(
    packet_loss_pct: Optional[float],
    avg_latency_ms: Optional[float],
    raw_output: str,
) -> str:
    text = raw_output.lower()

    if (
        "could not find host" in text
        or "name or service not known" in text
        or "temporary failure in name resolution" in text
    ):
        return "DNS resolution failure"

    if "destination host unreachable" in text:
        return "Destination host unreachable"

    if "general failure" in text:
        return "Local route or network stack problem"

    if packet_loss_pct is None:
        return "Could not parse ping result"

    if packet_loss_pct >= 100:
        return "Target unreachable or blocked"

    if packet_loss_pct >= 50:
        return "Severe packet loss"

    if packet_loss_pct > 0:
        return "Intermittent packet loss"

    if avg_latency_ms is not None and avg_latency_ms >= 200:
        return "High latency"

    return "OK"


def parse_ping_output(output: str) -> dict:
    text = output.strip()
    lower = text.lower()

    packet_loss_pct = None
    min_latency_ms = None
    avg_latency_ms = None
    max_latency_ms = None
    jitter_ms = None

    m = re.search(r"\((\d+)%\s+loss\)", text, re.IGNORECASE)
    if m:
        packet_loss_pct = float(m.group(1))

    if packet_loss_pct is None:
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s+packet loss", lower)
        if m:
            packet_loss_pct = float(m.group(1))

    m = re.search(
        r"minimum\s*=\s*(\d+)ms,\s*maximum\s*=\s*(\d+)ms,\s*average\s*=\s*(\d+)ms",
        lower,
    )
    if m:
        min_latency_ms = float(m.group(1))
        max_latency_ms = float(m.group(2))
        avg_latency_ms = float(m.group(3))

    if avg_latency_ms is None:
        m = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms", lower)
        if m:
            min_latency_ms = float(m.group(1))
            avg_latency_ms = float(m.group(2))
            max_latency_ms = float(m.group(3))
            jitter_ms = float(m.group(4))

    if (
        jitter_ms is None
        and min_latency_ms is not None
        and avg_latency_ms is not None
        and max_latency_ms is not None
    ):
        jitter_ms = round(
            statistics.pstdev([min_latency_ms, avg_latency_ms, max_latency_ms]),
            2,
        )

    probable_cause = infer_probable_cause(packet_loss_pct, avg_latency_ms, text)
    success = packet_loss_pct is not None and packet_loss_pct < 100

    return {
        "success": success,
        "packet_loss_pct": packet_loss_pct,
        "min_latency_ms": min_latency_ms,
        "avg_latency_ms": avg_latency_ms,
        "max_latency_ms": max_latency_ms,
        "jitter_ms": jitter_ms,
        "probable_cause": probable_cause,
        "raw_output": text,
    }


async def run_ping(target: str, count: int = PING_COUNT, timeout_ms: int = PING_TIMEOUT_MS) -> dict:
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    else:
        timeout_seconds = max(int(timeout_ms / 1000), 1)
        cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds), target]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    output = stdout.decode(errors="replace")
    return parse_ping_output(output)


def save_result(
    target: str,
    target_group: str,
    expected_state: str,
    result: dict,
    policy_status: str,
) -> None:
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO results (
            target, target_group, expected_state, checked_at, success,
            packet_loss_pct, min_latency_ms, avg_latency_ms, max_latency_ms,
            jitter_ms, probable_cause, policy_status, raw_output
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target,
            target_group,
            expected_state,
            utc_now_iso(),
            int(bool(result["success"])),
            result["packet_loss_pct"],
            result["min_latency_ms"],
            result["avg_latency_ms"],
            result["max_latency_ms"],
            result["jitter_ms"],
            result["probable_cause"],
            policy_status,
            result["raw_output"],
        ),
    )
    conn.commit()
    conn.close()


def get_local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception:
            return None


def get_windows_ipconfig_text() -> str:
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except Exception:
        return ""


def get_unix_ip_route_text() -> str:
    for cmd in (["ip", "route"], ["route", "-n"], ["netstat", "-rn"]):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if result.stdout.strip():
                return result.stdout
        except Exception:
            continue
    return ""


def get_gateway() -> Optional[str]:
    system = platform.system().lower()

    if system == "windows":
        text = get_windows_ipconfig_text()
        m = re.search(r"Default Gateway[ .:]*([\d.]+)", text, re.IGNORECASE)
        if m:
            return m.group(1)
        return None

    text = get_unix_ip_route_text()
    m = re.search(r"default via ([0-9.]+)", text)
    if m:
        return m.group(1)

    m = re.search(r"0\.0\.0\.0\s+([0-9.]+)", text)
    if m:
        return m.group(1)

    return None


def get_dns_servers() -> list[str]:
    servers: list[str] = []
    system = platform.system().lower()

    if system == "windows":
        text = get_windows_ipconfig_text()
        for line in text.splitlines():
            if "DNS Servers" in line:
                m = re.search(r"DNS Servers[ .:]*([\d.]+)", line, re.IGNORECASE)
                if m:
                    servers.append(m.group(1))
            elif servers:
                stripped = line.strip()
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", stripped):
                    servers.append(stripped)
                else:
                    # stop on first non-IP continuation
                    pass
    else:
        try:
            resolv = Path("/etc/resolv.conf")
            if resolv.exists():
                for line in resolv.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except Exception:
            pass

    seen = set()
    unique = []
    for server in servers:
        if server not in seen:
            seen.add(server)
            unique.append(server)
    return unique


def get_local_network() -> Optional[ipaddress.IPv4Network]:
    local_ip = get_local_ip()
    if not local_ip:
        return None

    try:
        ip = ipaddress.ip_address(local_ip)
        if ip.is_loopback:
            return None
    except Exception:
        return None

    # Best effort: assume /24
    try:
        return ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except Exception:
        return None


async def quick_ping_once(target: str) -> bool:
    try:
        result = await run_ping(target, count=1, timeout_ms=700)
        return bool(result["success"])
    except Exception:
        return False


async def discover_local_hosts() -> list[str]:
    network = get_local_network()
    if network is None:
        return []

    hosts = [str(ip) for ip in network.hosts()]
    hosts = hosts[:DISCOVERY_LIMIT]

    semaphore = asyncio.Semaphore(DISCOVERY_CONCURRENCY)
    live_hosts: list[str] = []

    async def worker(ip: str) -> None:
        async with semaphore:
            if await quick_ping_once(ip):
                live_hosts.append(ip)

    await asyncio.gather(*(worker(ip) for ip in hosts))
    live_hosts.sort(key=lambda x: tuple(int(part) for part in x.split(".")))
    return live_hosts


def evaluate_policy(expected_state: str, success: bool) -> str:
    if expected_state == "reachable":
        return "OK" if success else "NOT OK"
    if expected_state == "blocked":
        return "OK - blocked as expected" if not success else "NOT OK - should be blocked"
    return "UNKNOWN"


async def get_targets() -> list[dict]:
    targets: list[dict] = []
    seen = set()

    local_ip = get_local_ip()
    gateway = get_gateway()
    dns_servers = get_dns_servers()
    local_hosts = await discover_local_hosts()
    external_targets = read_targets_file(EXTERNAL_TARGETS_FILE)
    blocked_targets = read_targets_file(BLOCKED_TARGETS_FILE)

    def add_target(value: Optional[str], group: str, expected_state: str) -> None:
        if not value:
            return
        key = (value, group, expected_state)
        if key in seen:
            return
        seen.add(key)
        targets.append(
            {
                "target": value,
                "target_group": group,
                "expected_state": expected_state,
            }
        )

    add_target(local_ip, "local_self", "reachable")
    add_target(gateway, "local_gateway", "reachable")

    for dns in dns_servers:
        add_target(dns, "local_dns", "reachable")

    for host in local_hosts:
        add_target(host, "local_discovered", "reachable")

    for target in external_targets:
        add_target(target, "external", "reachable")

    for target in blocked_targets:
        add_target(target, "blocked_by_policy", "blocked")

    return targets


def get_latest_results() -> list[sqlite3.Row]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT r.*
        FROM results r
        INNER JOIN (
            SELECT target, target_group, MAX(id) AS max_id
            FROM results
            GROUP BY target, target_group
        ) latest
        ON r.id = latest.max_id
        ORDER BY r.target_group ASC, r.target ASC
        """
    ).fetchall()
    conn.close()
    return rows


def get_history(target: str, target_group: str, limit: int = 100) -> list[sqlite3.Row]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT *
        FROM results
        WHERE target = ? AND target_group = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (target, target_group, limit),
    ).fetchall()
    conn.close()
    return rows


def get_last_run_time() -> Optional[str]:
    conn = get_conn()
    row = conn.execute("SELECT MAX(checked_at) AS last_checked_at FROM results").fetchone()
    conn.close()
    return row["last_checked_at"] if row and row["last_checked_at"] else None


def badge_for_policy_status(policy_status: str) -> str:
    if policy_status.startswith("OK - blocked"):
        return '<span class="badge blue">Blocked as expected</span>'
    if policy_status == "OK":
        return '<span class="badge green">OK</span>'
    if policy_status.startswith("NOT OK - should be blocked"):
        return '<span class="badge red">Policy fail</span>'
    if policy_status == "NOT OK":
        return '<span class="badge red">Fail</span>'
    return '<span class="badge gray">Unknown</span>'


def group_label(group_name: str) -> str:
    mapping = {
        "local_self": "Local self",
        "local_gateway": "Local gateway",
        "local_dns": "Local DNS",
        "local_discovered": "Local discovered host",
        "external": "External internet",
        "blocked_by_policy": "Blocked by policy",
    }
    return mapping.get(group_name, group_name)


monitor_task: Optional[asyncio.Task] = None


async def monitoring_cycle() -> None:
    targets = await get_targets()

    for item in targets:
        target = item["target"]
        target_group = item["target_group"]
        expected_state = item["expected_state"]

        try:
            result = await run_ping(target, count=PING_COUNT, timeout_ms=PING_TIMEOUT_MS)
        except Exception as exc:
            result = {
                "success": False,
                "packet_loss_pct": None,
                "min_latency_ms": None,
                "avg_latency_ms": None,
                "max_latency_ms": None,
                "jitter_ms": None,
                "probable_cause": f"Monitor error: {exc}",
                "raw_output": str(exc),
            }

        policy_status = evaluate_policy(expected_state, bool(result["success"]))
        save_result(target, target_group, expected_state, result, policy_status)

        print(
            f"[{utc_now_iso()}] "
            f"{target_group} {target} "
            f"success={result['success']} "
            f"loss={result['packet_loss_pct']} "
            f"policy={policy_status}"
        )


async def monitor_loop() -> None:
    while True:
        await monitoring_cycle()
        await asyncio.sleep(INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_task
    ensure_files_exist()
    init_db()
    monitor_task = asyncio.create_task(monitor_loop())
    yield
    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Auto Network Monitor",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    rows = get_latest_results()
    last_checked = get_last_run_time() or "No checks yet"
    local_ip = get_local_ip() or "Unknown"
    gateway = get_gateway() or "Unknown"
    network = str(get_local_network() or "Unknown")
    dns_servers = ", ".join(get_dns_servers()) or "None"

    table_rows = ""
    for row in rows:
        target = html.escape(str(row["target"]))
        target_group = html.escape(group_label(str(row["target_group"])))
        expected_state = html.escape(str(row["expected_state"]))
        checked_at = html.escape(str(row["checked_at"]))

        packet_loss = "null" if row["packet_loss_pct"] is None else f"{row['packet_loss_pct']}%"
        avg_latency = "null" if row["avg_latency_ms"] is None else f"{row['avg_latency_ms']} ms"
        probable_cause = html.escape(str(row["probable_cause"] or ""))
        policy_status = html.escape(str(row["policy_status"] or ""))
        status_badge = badge_for_policy_status(str(row["policy_status"] or ""))

        history_url = f"/history/{target}?group={row['target_group']}"

        table_rows += f"""
        <tr>
            <td>{status_badge}</td>
            <td>{target}</td>
            <td>{target_group}</td>
            <td>{expected_state}</td>
            <td>{packet_loss}</td>
            <td>{avg_latency}</td>
            <td>{probable_cause}</td>
            <td>{policy_status}</td>
            <td>{checked_at}</td>
            <td><a href="{history_url}">History</a></td>
        </tr>
        """

    if not table_rows:
        table_rows = """
        <tr>
            <td colspan="10">No results yet. Wait for the first monitoring cycle to finish.</td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <title>Auto Network Monitor</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 1400px;
                margin: 40px auto;
                padding: 0 20px;
                background: #f5f7fb;
                color: #111;
            }}
            .card {{
                background: white;
                padding: 24px;
                border-radius: 12px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.08);
                margin-bottom: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #e5e7eb;
                vertical-align: top;
                font-size: 14px;
            }}
            th {{
                background: #f9fafb;
            }}
            .badge {{
                display: inline-block;
                padding: 4px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: bold;
                white-space: nowrap;
            }}
            .green {{ background: #dcfce7; color: #166534; }}
            .red {{ background: #fee2e2; color: #991b1b; }}
            .blue {{ background: #dbeafe; color: #1d4ed8; }}
            .gray {{ background: #e5e7eb; color: #374151; }}
            a {{
                color: #0b57d0;
                text-decoration: none;
            }}
            code {{
                background: #eef2ff;
                padding: 2px 6px;
                border-radius: 6px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Auto Network Monitor</h1>
            <p><strong>Local IP:</strong> {html.escape(local_ip)}</p>
            <p><strong>Detected network:</strong> {html.escape(network)}</p>
            <p><strong>Gateway:</strong> {html.escape(gateway)}</p>
            <p><strong>DNS:</strong> {html.escape(dns_servers)}</p>
            <p><strong>Ping count per target:</strong> {PING_COUNT}</p>
            <p><strong>Interval:</strong> every 15 minutes</p>
            <p><strong>Last completed save:</strong> {html.escape(last_checked)}</p>
            <p><strong>External targets file:</strong> <code>external_targets.txt</code></p>
            <p><strong>Blocked targets file:</strong> <code>blocked_targets.txt</code></p>
        </div>

        <div class="card">
            <h2>Latest Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Target</th>
                        <th>Group</th>
                        <th>Expected</th>
                        <th>Packet Loss</th>
                        <th>Average Latency</th>
                        <th>Probable Cause</th>
                        <th>Policy Status</th>
                        <th>Checked At (UTC)</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """


@app.get("/history/{target:path}", response_class=HTMLResponse)
def history_page(target: str, group: str) -> str:
    rows = get_history(target, group, limit=100)
    safe_target = html.escape(target)
    safe_group = html.escape(group_label(group))

    history_rows = ""
    for row in rows:
        checked_at = html.escape(str(row["checked_at"]))
        success = "Yes" if row["success"] else "No"
        packet_loss = "null" if row["packet_loss_pct"] is None else f"{row['packet_loss_pct']}%"
        avg_latency = "null" if row["avg_latency_ms"] is None else f"{row['avg_latency_ms']} ms"
        probable_cause = html.escape(str(row["probable_cause"] or ""))
        policy_status = html.escape(str(row["policy_status"] or ""))

        history_rows += f"""
        <tr>
            <td>{checked_at}</td>
            <td>{success}</td>
            <td>{packet_loss}</td>
            <td>{avg_latency}</td>
            <td>{probable_cause}</td>
            <td>{policy_status}</td>
        </tr>
        """

    if not history_rows:
        history_rows = '<tr><td colspan="6">No history found for this target.</td></tr>'

    latest_raw = ""
    if rows:
        latest_raw = html.escape(str(rows[0]["raw_output"] or ""))

    return f"""
    <html>
    <head>
        <title>History - {safe_target}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 1200px;
                margin: 40px auto;
                padding: 0 20px;
                background: #f5f7fb;
            }}
            .card {{
                background: white;
                padding: 24px;
                border-radius: 12px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.08);
                margin-bottom: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #e5e7eb;
                vertical-align: top;
            }}
            pre {{
                white-space: pre-wrap;
                background: #f9fafb;
                padding: 14px;
                border-radius: 8px;
                overflow-x: auto;
            }}
            a {{
                color: #0b57d0;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>History for {safe_target}</h1>
            <p><strong>Group:</strong> {safe_group}</p>
            <p><a href="/">Back to dashboard</a></p>
        </div>

        <div class="card">
            <h2>Saved Checks</h2>
            <table>
                <thead>
                    <tr>
                        <th>Checked At (UTC)</th>
                        <th>Success</th>
                        <th>Packet Loss</th>
                        <th>Average Latency</th>
                        <th>Probable Cause</th>
                        <th>Policy Status</th>
                    </tr>
                </thead>
                <tbody>
                    {history_rows}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Latest Raw Ping Output</h2>
            <pre>{latest_raw}</pre>
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("network_monitor_auto:app", host="127.0.0.1", port=8000, reload=False)
