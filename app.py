import platform
import re
import subprocess

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

app = FastAPI()


def run_ping(host: str) -> dict:
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "4", host]
    else:
        cmd = ["ping", "-c", "4", host]

    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr

    packet_loss = "Unknown"
    avg_latency = "Unknown"

    loss_match = re.search(r"\((\d+)%\s+loss\)", output, re.IGNORECASE)
    if loss_match:
        packet_loss = f"{loss_match.group(1)}%"
    else:
        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", output, re.IGNORECASE)
        if loss_match:
            packet_loss = f"{loss_match.group(1)}%"

    avg_match = re.search(
        r"minimum\s*=\s*\d+ms,\s*maximum\s*=\s*\d+ms,\s*average\s*=\s*(\d+)ms",
        output,
        re.IGNORECASE,
    )
    if avg_match:
        avg_latency = f"{avg_match.group(1)} ms"
    else:
        avg_match = re.search(r"=\s*[\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+\s*ms", output)
        if avg_match:
            avg_latency = f"{avg_match.group(1)} ms"

    return {
        "host": host,
        "packet_loss": packet_loss,
        "avg_latency": avg_latency,
        "raw_output": output,
    }


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
        <title>Ping Checker</title>
        <style>
            body { font-family: Arial; max-width: 800px; margin: 40px auto; }
            input, button { padding: 10px; font-size: 16px; }
            input { width: 300px; }
            pre { background: #f4f4f4; padding: 15px; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <h1>Ping Checker</h1>
        <form method="post" action="/check">
            <input type="text" name="host" placeholder="Enter IP or hostname, e.g. 8.8.8.8" required>
            <button type="submit">Run Test</button>
        </form>
    </body>
    </html>
    """


@app.post("/check", response_class=HTMLResponse)
def check(host: str = Form(...)):
    result = run_ping(host)

    return f"""
    <html>
    <head>
        <title>Ping Result</title>
        <style>
            body {{ font-family: Arial; max-width: 800px; margin: 40px auto; }}
            pre {{ background: #f4f4f4; padding: 15px; white-space: pre-wrap; }}
            a {{ display: inline-block; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <h1>Result</h1>
        <p><strong>Host:</strong> {result["host"]}</p>
        <p><strong>Packet loss:</strong> {result["packet_loss"]}</p>
        <p><strong>Average latency:</strong> {result["avg_latency"]}</p>

        <h2>Raw ping output</h2>
        <pre>{result["raw_output"]}</pre>

        <a href="/">Run another test</a>
    </body>
    </html>
    """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)