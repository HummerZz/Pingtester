import asyncio
import html
import platform
import re
import sqlite3
import statistics
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

DB_PATH = Path("network_monitor.db")
IPS_FILE = Path("ips.txt")

PING_COUNT = 20
INTERVAL_SECONDS = 15 * 60
PING_TIMEOUT_MS = 1000


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
            ip TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            success INTEGER NOT NULL,
            packet_loss_pct REAL,
            min_latency_ms REAL,
            avg_latency_ms REAL,
            max_latency_ms REAL,
            jitter_ms REAL,
            probable_cause TEXT,
            raw_output TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_results_ip_checked_at
        ON results(ip, checked_at DESC)
        """
    )

    conn.commit()
    conn.close()


def read_ips() -> list[str]:
    if not IPS_FILE.exists():
        IPS_FILE.write_text("8.8.8.8\n1.1.1.1\n", encoding="utf-8")

    ips: list[str] = []
    for line in IPS_FILE.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        ips.append(value)

    # remove duplicates, keep order
    seen = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    return unique_ips


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
        return "Local network stack or route problem"

    if packet_loss_pct is None:
        return "Could not parse ping result"

    if packet_loss_pct >= 100:
        return "Host unreachable or blocked by firewall"

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

    # Windows packet loss: (0% loss)
    m = re.search(r"\((\d+)%\s+loss\)", text, re.IGNORECASE)
    if m:
        packet_loss_pct = float(m.group(1))

    # Linux/macOS packet loss: 0% packet loss / 0.0% packet loss
    if packet_loss_pct is None:
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s+packet loss", lower)
        if m:
            packet_loss_pct = float(m.group(1))

    # Windows latency: Minimum = 11ms, Maximum = 13ms, Average = 12ms
    m = re.search(
        r"minimum\s*=\s*(\d+)ms,\s*maximum\s*=\s*(\d+)ms,\s*average\s*=\s*(\d+)ms",
        lower,
    )
    if m:
        min_latency_ms = float(m.group(1))
        max_latency_ms = float(m.group(2))
        avg_latency_ms = float(m.group(3))

    # Linux/macOS latency: min/avg/max/mdev = 11.1/12.2/13.3/0.5 ms
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


async def run_ping(ip: str) -> dict:
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT_MS), ip]
    else:
        timeout_seconds = max(int(PING_TIMEOUT_MS / 1000), 1)
        cmd = ["ping", "-c", str(PING_COUNT), "-W", str(timeout_seconds), ip]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    output = stdout.decode(errors="replace")
    return parse_ping_output(output)


def save_result(ip: str, result: dict) -> None:
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO results (
            ip, checked_at, success, packet_loss_pct, min_latency_ms, avg_latency_ms,
            max_latency_ms, jitter_ms, probable_cause, raw_output
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ip,
            utc_now_iso(),
            int(bool(result["success"])),
            result["packet_loss_pct"],
            result["min_latency_ms"],
            result["avg_latency_ms"],
            result["max_latency_ms"],
            result["jitter_ms"],
            result["probable_cause"],
            result["raw_output"],
        ),
    )
    conn.commit()
    conn.close()


def get_latest_results() -> list[sqlite3.Row]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT r.*
        FROM results r
        INNER JOIN (
            SELECT ip, MAX(id) AS max_id
            FROM results
            GROUP BY ip
        ) latest
        ON r.id = latest.max_id
        ORDER BY r.ip ASC
        """
    ).fetchall()
    conn.close()
    return rows


def get_history_for_ip(ip: str, limit: int = 50) -> list[sqlite3.Row]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT *
        FROM results
        WHERE ip = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (ip, limit),
    ).fetchall()
    conn.close()
    return rows


def count_total_ips() -> int:
    return len(read_ips())


def last_run_time() -> Optional[str]:
    conn = get_conn()
    row = conn.execute("SELECT MAX(checked_at) AS last_checked_at FROM results").fetchone()
    conn.close()
    return row["last_checked_at"] if row and row["last_checked_at"] else None


def get_status_badge(row: sqlite3.Row) -> str:
    loss = row["packet_loss_pct"]
    if loss is None:
        return '<span class="badge gray">No data</span>'
    if loss >= 100:
        return '<span class="badge red">Down</span>'
    if loss > 0:
        return '<span class="badge orange">Unstable</span>'
    return '<span class="badge green">OK</span>'


monitor_task: Optional[asyncio.Task] = None


async def monitor_loop() -> None:
    while True:
        ips = read_ips()

        for ip in ips:
            try:
                result = await run_ping(ip)
                save_result(ip, result)
                print(
                    f"[{utc_now_iso()}] {ip} "
                    f"loss={result['packet_loss_pct']} avg={result['avg_latency_ms']}"
                )
            except Exception as exc:
                save_result(
                    ip,
                    {
                        "success": False,
                        "packet_loss_pct": None,
                        "min_latency_ms": None,
                        "avg_latency_ms": None,
                        "max_latency_ms": None,
                        "jitter_ms": None,
                        "probable_cause": f"Monitor error: {exc}",
                        "raw_output": str(exc),
                    },
                )
                print(f"[{utc_now_iso()}] {ip} ERROR: {exc}")

        await asyncio.sleep(INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_task
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
    title="24/7 Network Monitor",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "ok"


@app.get("/ips", response_class=HTMLResponse)
def ips_page() -> str:
    ips = read_ips()
    items = "".join(f"<li>{html.escape(ip)}</li>" for ip in ips)
    return f"""
    <html>
    <head>
        <title>IP List</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; }}
            .card {{ background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
            body {{ background: #f5f7fb; }}
            a {{ color: #0b57d0; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>IP List</h1>
            <p>Edit <code>ips.txt</code> to change the monitored addresses.</p>
            <ul>{items}</ul>
            <p><a href="/">Back to dashboard</a></p>
        </div>
    </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    rows = get_latest_results()
    total_ips = count_total_ips()
    last_checked = last_run_time() or "No checks yet"

    table_rows = ""
    for row in rows:
        ip = html.escape(row["ip"])
        checked_at = html.escape(str(row["checked_at"] or ""))
        packet_loss = "null" if row["packet_loss_pct"] is None else f"{row['packet_loss_pct']}%"
        avg_latency = "null" if row["avg_latency_ms"] is None else f"{row['avg_latency_ms']} ms"
        probable_cause = html.escape(str(row["probable_cause"] or ""))
        raw_link = f"/history/{ip}"
        status = get_status_badge(row)

        table_rows += f"""
        <tr>
            <td>{status}</td>
            <td>{ip}</td>
            <td>{packet_loss}</td>
            <td>{avg_latency}</td>
            <td>{probable_cause}</td>
            <td>{checked_at}</td>
            <td><a href="{raw_link}">History</a></td>
        </tr>
        """

    if not table_rows:
        table_rows = """
        <tr>
            <td colspan="7">No results yet. Wait for the first run, or restart after editing ips.txt.</td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <title>24/7 Network Monitor</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 1200px;
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
            }}
            .green {{ background: #dcfce7; color: #166534; }}
            .orange {{ background: #ffedd5; color: #9a3412; }}
            .red {{ background: #fee2e2; color: #991b1b; }}
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
            <h1>24/7 Network Monitor</h1>
            <p><strong>Monitored IPs:</strong> {total_ips}</p>
            <p><strong>Ping count per IP:</strong> {PING_COUNT}</p>
            <p><strong>Interval:</strong> every 15 minutes</p>
            <p><strong>Last completed save:</strong> {html.escape(last_checked)}</p>
            <p><a href="/ips">View IP list</a></p>
            <p>Edit <code>ips.txt</code> to add or remove IP addresses.</p>
        </div>

        <div class="card">
            <h2>Latest Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>IP</th>
                        <th>Packet Loss</th>
                        <th>Average Latency</th>
                        <th>Probable Cause</th>
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


@app.get("/history/{ip:path}", response_class=HTMLResponse)
def history_page(ip: str) -> str:
    rows = get_history_for_ip(ip, limit=100)
    safe_ip = html.escape(ip)

    history_rows = ""
    for row in rows:
        packet_loss = "null" if row["packet_loss_pct"] is None else f"{row['packet_loss_pct']}%"
        avg_latency = "null" if row["avg_latency_ms"] is None else f"{row['avg_latency_ms']} ms"
        probable_cause = html.escape(str(row["probable_cause"] or ""))
        checked_at = html.escape(str(row["checked_at"] or ""))
        success = "Yes" if row["success"] else "No"

        history_rows += f"""
        <tr>
            <td>{checked_at}</td>
            <td>{success}</td>
            <td>{packet_loss}</td>
            <td>{avg_latency}</td>
            <td>{probable_cause}</td>
        </tr>
        """

    if not history_rows:
        history_rows = '<tr><td colspan="5">No history found for this IP.</td></tr>'

    latest_raw = ""
    if rows:
        latest_raw = html.escape(str(rows[0]["raw_output"] or ""))

    return f"""
    <html>
    <head>
        <title>History - {safe_ip}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 1100px;
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
            a {{ color: #0b57d0; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>History for {safe_ip}</h1>
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

    uvicorn.run("network_monitor:app", host="127.0.0.1", port=8000, reload=False)
