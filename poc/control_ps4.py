#!/usr/bin/env python3
"""
Tool A: PS4 Control Panel (runs on Termux)
Sends commands to the PS4 browser agent (Tool B) via HTTP polling.
"""
import urllib.request
import urllib.parse
import json
import time
import sys
import os

SERVER = 'http://127.0.0.1:8080'
PS4_BROWSER = None

def send_cmd(action, args=None):
    """Queue a command for the PS4 browser agent"""
    args = args or []
    args_str = json.dumps(args)
    url = f'{SERVER}/enqueue?action={urllib.parse.quote(action)}&args={urllib.parse.quote(args_str)}'
    try:
        urllib.request.urlopen(url, timeout=3)
        print(f'[CMD] {action}: {args}')
    except Exception as e:
        print(f'[CMD ERROR] {e}')

def get_results():
    """Get all results from the browser agent"""
    try:
        req = urllib.request.urlopen(f'{SERVER}/results', timeout=5)
        data = json.loads(req.read().decode())
        return data
    except Exception as e:
        return [{'error': str(e)}]

def get_log():
    """Get the log file"""
    try:
        req = urllib.request.urlopen(f'{SERVER}/readlog', timeout=5)
        return req.read().decode()
    except Exception as e:
        return f'Error: {e}'

def check_browser():
    """Check if the browser agent is alive"""
    try:
        req = urllib.request.urlopen(f'{SERVER}/readlog', timeout=3)
        content = req.read().decode()
        return 'Browser Agent started' in content or len(content) > 0
    except:
        return False

def interactive():
    """Interactive command mode"""
    print('=== PS4 Browser Agent Control ===')
    print(f'Server: {SERVER}')
    print()
    print('Available commands:')
    print('  info        - Get PS4 system info')
    print('  api_check   - Check available APIs')
    print('  spray [N] [SIZE] - Heap spray')
    print('  feature X   - Test specific feature')
    print('  cve         - Test CVE-2026-43705')
    print('  layout      - Explore memory layout')
    print('  plugins     - Check plugins')
    print('  timing      - Check performance timing')
    print('  log         - View PS4 log')
    print('  results     - View all results')
    print('  raw CMD     - Send raw command JSON')
    print('  quit        - Exit')
    print()
    
    while True:
        try:
            cmd = input('PS4> ').strip()
            if not cmd:
                continue
            
            if cmd == 'quit' or cmd == 'exit':
                break
            elif cmd == 'log':
                print(get_log())
            elif cmd == 'results':
                results = get_results()
                for r in results:
                    if 'tag' in r:
                        print(f"  [{r['tag']}] {r['result'][:200]}")
                    elif 'error' in r:
                        print(f"  [ERROR] {r['error']}")
            elif cmd.startswith('spray'):
                parts = cmd.split()
                count = int(parts[1]) if len(parts) > 1 else 100
                size = int(parts[2]) if len(parts) > 2 else 256
                send_cmd('spray', [count, size])
            elif cmd.startswith('feature'):
                parts = cmd.split(maxsplit=1)
                feature = parts[1] if len(parts) > 1 else 'sharedarraybuffer'
                send_cmd('test_feature', [feature])
            elif cmd == 'info':
                send_cmd('info')
            elif cmd == 'api_check':
                send_cmd('api_check')
            elif cmd == 'cve':
                send_cmd('cve_test')
            elif cmd == 'layout':
                send_cmd('explore_layout')
            elif cmd == 'plugins':
                send_cmd('plugins')
            elif cmd == 'timing':
                send_cmd('timing')
            elif cmd.startswith('{'):
                # Raw JSON command
                try:
                    raw = json.loads(cmd)
                    send_cmd(raw.get('action', ''), raw.get('args', []))
                except:
                    print('Invalid JSON')
            else:
                print(f'Unknown command: {cmd}')
            
            # Wait and check for results
            time.sleep(1)
            results = get_results()
            if results:
                latest = results[-1]
                if 'tag' in latest:
                    print(f"  [{latest['tag']}] {latest['result'][:500]}")
                elif 'error' in latest:
                    print(f"  [ERROR] {latest['error']}")
                    
        except KeyboardInterrupt:
            print('\nExiting...')
            break
        except EOFError:
            break

def batch_exploit():
    """Run a sequence of exploration commands"""
    print('=== Running Batch Exploit Exploration ===')
    
    commands = [
        ('info', []),
        ('api_check', []),
        ('plugins', []),
        ('timing', []),
        ('test_feature', ['sharedarraybuffer']),
        ('test_feature', ['webworker']),
        ('explore_layout', []),
        ('cve_test', []),
        ('spray', [200, 512]),
        ('explore_layout', []),
    ]
    
    for action, args in commands:
        print(f'\n>> Sending: {action} {args}')
        send_cmd(action, args)
        time.sleep(1.5)
        
        results = get_results()
        if results:
            latest = results[-1]
            if 'tag' in latest:
                print(f"  RESULT: {latest['result'][:500]}")
            elif 'error' in latest:
                print(f"  ERROR: {latest['error']}")
        else:
            print('  No results yet')
    
    print('\n=== Batch Complete ===')
    print('\nFull log:')
    print(get_log())

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'batch':
        batch_exploit()
    else:
        interactive()
