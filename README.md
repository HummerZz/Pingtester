# 24/7 Network Monitor

A simple local monitoring app that runs 24/7, pings a list of IP addresses every 15 minutes, and stores the results in a SQLite database.

## What it does

- Reads IP addresses from `ips.txt`
- Pings each IP **20 times**
- Repeats the checks every **15 minutes**
- Saves the results in `network_monitor.db`
- Shows the latest status in a browser
- Shows history for each IP

## Files

You should have these files in the same folder:

```text
network_monitor.py
ips.txt

After the program starts, it will also create:

network_monitor.db
Requirements

Python 3 installed

Windows, Linux, or macOS

Network access to the IP addresses you want to monitor

Install

Open a terminal in the same folder as network_monitor.py and run:

pip install fastapi uvicorn
Configure the IP list

Edit ips.txt and put one IP address per line.

Example:

10.10.2.1
10.10.3.1
10.10.3.5
10.10.3.4
8.8.8.8
1.1.1.1

Notes:

Empty lines are ignored

Lines starting with # are ignored

Duplicate IPs are automatically removed

Example with comments:

# Gateway
10.10.2.1

# Internal DNS
10.10.3.1
10.10.3.5
10.10.3.4

# External test targets
8.8.8.8
1.1.1.1
Start the program

Run:

python network_monitor.py
Open in browser

Go to:

http://127.0.0.1:8000
How it works

The app starts a background monitoring loop when it launches.

For each cycle it will:

Read all IP addresses from ips.txt

Ping each IP 20 times

Save the result

Wait 15 minutes

Repeat

What you see on the dashboard

The main page shows the latest result for each IP.

You will see:

Status

IP

Packet Loss

Average Latency

Probable Cause

Checked At

History link

Status meanings

OK = no packet loss

Unstable = some packet loss

Down = 100% packet loss

No data = no saved result yet

History page

Click History next to an IP to view:

previous saved checks

packet loss over time

average latency over time

latest raw ping output

Health check

You can also open:

http://127.0.0.1:8000/health

If the app is running, it returns:

ok
Changing the IP list

To add or remove monitored IPs:

Open ips.txt

Edit the list

Save the file

The program reads the file again on the next monitoring cycle.

Important notes

This app is designed to run continuously

It stores data locally in SQLite

It does not need a separate database server

It uses the system ping command

The first dashboard may show no results until the first checks have finished

Example workflow

Add IPs to ips.txt

Start the app

Open http://127.0.0.1:8000

Wait for the first monitoring cycle to finish

View the latest status and open history for details

Stop the program

Press:

Ctrl + C

in the terminal.
