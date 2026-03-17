# Ping Checker

A very simple local web app that lets you enter an IP address or hostname, run a ping test, and view the result in the browser.

## What it does

- You enter a host, for example `8.8.8.8`
- The app runs a ping test
- It shows:
  - packet loss
  - average latency
  - raw ping output

## Requirements

- Python 3 installed
- Internet/network access
- Windows, Linux, or macOS

## Install

Open terminal in the same folder as `app.py` and run:

```bash
pip install fastapi uvicorn python-multipart
Start the app

Run:

python app.py
Open in browser

Go to:

http://127.0.0.1:8000
How to use

Open the page in your browser

Enter an IP address or hostname, for example:

8.8.8.8

google.com

Click Run Test

Read the result on the next page

What the result means

Host = the address you tested

Packet loss = how many packets were lost

Average latency = average response time

Raw ping output = the full ping result from your system

Example

If you test:

8.8.8.8

the app will ping it 4 times and show the result in the browser.

Stop the app

Press:

Ctrl + C

in the terminal.