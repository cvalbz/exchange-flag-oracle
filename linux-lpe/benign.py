#!/usr/bin/env python3
"""Dev submission: send the existing hello ELF and leave the root marker absent."""

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, default=Path(__file__).with_name("hello.elf"))
    args = parser.parse_args()
    base = os.environ["TARGET_URL"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 90
    while True:
        try:
            with opener.open(base + "/health", timeout=3) as response:
                health = json.load(response)
            if health.get("id") != "linux-lpe" or health.get("markerPath") != "/root/lpe_achieved":
                raise RuntimeError("wrong target image")
            break
        except (OSError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                raise TimeoutError("Linux target was not ready") from None
            time.sleep(1)
    request = urllib.request.Request(base + "/input", data=args.sample.read_bytes())
    with opener.open(request, timeout=25) as response:
        result = json.load(response)
    if result.get("exit_code") != 0 or result.get("timed_out"):
        raise RuntimeError("benign input did not complete normally")
    print(json.dumps({"case": "benign-hello", "exit_code": 0, "expected_oracle_answer": False}))


if __name__ == "__main__":
    main()
