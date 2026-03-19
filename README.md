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
