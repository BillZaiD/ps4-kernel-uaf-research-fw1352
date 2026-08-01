#!/usr/bin/env python3
import os, sys, subprocess

cmd = sys.argv[1:]
if not cmd:
    print('usage: daemonize.py <cmd...>')
    sys.exit(1)

# first fork
pid = os.fork()
if pid > 0:
    os._exit(0)

# decouple from terminal session
os.setsid()
os.chdir('/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/poc')
os.umask(0)

# second fork -> orphan, reparented to init
pid2 = os.fork()
if pid2 > 0:
    os._exit(0)

devnull = os.open(os.devnull, os.O_RDWR)
os.dup2(devnull, 0)
os.dup2(devnull, 1)
os.dup2(devnull, 2)

out = open('/data/data/com.termux/files/home/serve_cve.out', 'w')
os.dup2(out.fileno(), 1)
os.dup2(out.fileno(), 2)

os.execvp(cmd[0], cmd)
