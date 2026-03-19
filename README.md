# Auto Network Monitor

A single-file Python app that automatically discovers the local network, monitors local and external connectivity, and checks whether some targets are blocked by firewall as expected.

## What it does

This program runs continuously and:

- detects the local machine IP
- detects the local network
- detects the default gateway
- detects DNS servers
- discovers responding hosts on the local network
- checks external internet targets
- checks targets that are expected to be blocked by firewall
- sends **20 pings per target**
- repeats every **15 minutes**
- stores results in SQLite
- shows the latest status and history in a browser

## Files

Place these files in the same folder:

```text
network_monitor_auto.py
external_targets.txt
blocked_targets.txt

After the app starts, it will create:

network_monitor_auto.db
Requirements

Python 3

Windows, Linux, or macOS

permission to run the system ping command

network access to the systems you want to test

Install

Open a terminal in the same folder and run:

pip install fastapi uvicorn
Configuration
1. External targets

Edit external_targets.txt.

Put one IP address or hostname per line.

Example:

8.8.8.8
1.1.1.1
google.com

These are targets that should normally be reachable from the network.

2. Blocked targets

Edit blocked_targets.txt.

Put one IP address or hostname per line.

Example:

203.0.113.10
example-blocked-host.local

These are targets that are expected to be blocked by firewall or policy.

If they do not respond, that is treated as correct behavior.

If they do respond, the program marks that as a policy problem.

Start the program

Run:

python network_monitor_auto.py
Open in browser

Go to:

http://127.0.0.1:8000
How it works

When the program starts, it automatically tries to detect:

local IP

local /24 network

default gateway

DNS servers

Then it:

discovers responding hosts on the local network

builds a target list from:

local machine

gateway

DNS servers

discovered local hosts

external_targets.txt

blocked_targets.txt

pings every target 20 times

saves the results

waits 15 minutes

repeats forever

Dashboard

The main page shows the latest result for each target.

Columns include:

Status

Target

Group

Expected

Packet Loss

Average Latency

Probable Cause

Policy Status

Checked At

History

Target groups

The program can classify targets into these groups:

Local self

Local gateway

Local DNS

Local discovered host

External internet

Blocked by policy

Status meaning
Expected = reachable

These targets should answer.

success = OK

failure = NOT OK

Expected = blocked

These targets should not answer.

no response = OK - blocked as expected

response = NOT OK - should be blocked

Policy examples
Example 1: Normal internet target

If 8.8.8.8 replies:

policy status = OK

If 8.8.8.8 does not reply:

policy status = NOT OK

Example 2: Firewall-blocked target

If a target in blocked_targets.txt does not reply:

policy status = OK - blocked as expected

If it does reply:

policy status = NOT OK - should be blocked

History page

Click History next to any row on the dashboard.

The history page shows:

previous checks

packet loss over time

average latency over time

probable cause

policy status

latest raw ping output

Health check

You can also open:

http://127.0.0.1:8000/health

If the service is running, it returns:

ok
Notes about local discovery

The program tries to discover the local network automatically.

Important details:

it currently assumes a /24 local network

it only checks up to 254 hosts during discovery

it discovers hosts by sending a quick ping

only hosts that respond are added as discovered local hosts

Database

Results are stored in:

network_monitor_auto.db

The database is local and created automatically.

Stop the program

Press:

Ctrl + C

in the terminal.
