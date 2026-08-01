#!/usr/bin/env python3
"""Stage-1 CSSFontFace UAF trigger test driver.
Waits for the PS4 browser agent to connect, then runs uaf_api_probe and stage1_uaf.
Usage: stage1_run.py            (waits up to 60s for the browser)
       stage1_run.py quick      (skip probe, run stage1 immediately)
"""
import urllib.request
import urllib.parse
import json
import time
import sys

SERVER = 'http://127.0.0.1:8080'

def get(url):
    return urllib.request.urlopen(url, timeout=5).read().decode()

def enqueue(action, args=None):
    args = args or []
    get(f'{SERVER}/enqueue?action={urllib.parse.quote(action)}&args={urllib.parse.quote(json.dumps(args))}')

def drain(tag, wait):
    """Wait for a result with the given tag; return result string or None."""
    deadline = time.time() + wait
    seen = set()
    while time.time() < deadline:
        try:
            res = json.loads(get(f'{SERVER}/results'))
        except Exception:
            time.sleep(0.5)
            continue
        for r in res:
            key = (r.get('tag'), r.get('result', '')[:30])
            if r.get('tag') == tag and key not in seen:
                seen.add(key)
                return r.get('result')
        time.sleep(0.5)
    return None

def wait_browser(wait):
    print(f'[*] Waiting up to {wait}s for the PS4 browser agent...', flush=True)
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            res = json.loads(get(f'{SERVER}/results'))
            if res:
                print(f'[+] Browser is responding (last result tag: {res[-1].get("tag")})', flush=True)
                return True
        except Exception:
            pass
        time.sleep(1)
    return False

if __name__ == '__main__':
    quick = len(sys.argv) > 1 and sys.argv[1] == 'quick'
    if not quick:
        if not wait_browser(60):
            print('[-] Browser agent not seen. Open the PS4 browser to:')
            print('    http://192.168.100.2:8080/browser_agent.html')
            print('    (reload if already open) then re-run this script.')
            sys.exit(1)

    # Phase A: API probe
    enqueue('uaf_api_probe', [])
    r = drain('uaf_api_probe', 15)
    print('=== uaf_api_probe ===')
    print(r if r is not None else '(no result received)')
    print()

    # Phase B: Stage-1 UAF trigger
    print('[*] Running stage1_uaf... (up to ~40s; browser crash = negative-ish signal)', flush=True)
    enqueue('stage1_uaf', [])
    r = drain('stage1_uaf', 45)
    print('=== stage1_uaf ===')
    print(r if r is not None else '(no result — browser may have crashed or hung)')
    print()
    print('[*] Full log:')
    print(get(f'{SERVER}/readlog'))
