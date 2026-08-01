#!/usr/bin/env python3
"""
PS4 FW 13.52 Advanced Fuzzer — Persistent | Resumable | Kali-Integrated
========================================================================
- ينتظر إلى الأبد حتى تعود PS4 وتفتح المنفذ
- يستأنف من حيث توقف (حتى لو أعيد تشغيل الجهاز)
- يدمج nmap و scapy (إذا كانت متوفرة)
- استراتيجيات متعددة: basic, buffer, edge, exhaustive, random, mutation, boundary
"""

import socket, struct, time, json, os, sys, signal, random, re, copy
import subprocess, threading
from datetime import datetime
from collections import defaultdict, OrderedDict
from typing import Optional, List, Tuple, Dict, Set, Callable, Any

# ─── Config ────────────────────────────────────────────────────
PS4_HOST          = "192.168.100.61"
PS4_PORT          = 9026
RETRY_INTERVAL    = 15        # seconds between retry attempts
SOCKET_TIMEOUT    = 30
BATCH_SIZE        = 60        # tests per Lua payload
BATCH_DELAY       = 0.3       # seconds between batches
LOG_DIR           = "/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/fuzz_logs"

os.makedirs(LOG_DIR, exist_ok=True)

# ─── HLL: uint64 as hi/lo pair ─────────────────────────────────
class HLL:
    __slots__ = ('h','l')
    def __init__(self, h=0, l=0):
        self.h = h & 0xFFFFFFFF
        self.l = l & 0xFFFFFFFF
    @staticmethod
    def from_64(v): return HLL((v>>32)&0xFFFFFFFF, v&0xFFFFFFFF)
    def to_64(self): return (self.h<<32)|self.l
    def is_minus1(self): return self.h==0xFFFFFFFF and self.l==0xFFFFFFFF
    def is_zero(self): return self.h==0 and self.l==0
    def is_kptr(self): return 0xFFFF8000 <= self.h <= 0xFFFFFFFF
    def __eq__(self, o): return isinstance(o,HLL) and self.h==o.h and self.l==o.l
    def __hash__(self): return hash((self.h,self.l))
    def __repr__(self): return f"0x{self.h:08x}{self.l:08x}"

# ─── FuzzResult ────────────────────────────────────────────────
class FuzzResult:
    __slots__ = ('scno','name','status','hll','ts')
    STATUS_OK     = 'O'   # returned uint64
    STATUS_CRASH  = 'C'   # pcall failed
    STATUS_NOWRAP = 'N'   # no wrapper
    STATUS_RAW    = 'R'   # raw non-table return
    def __init__(self, scno:int, name:str, status:str, hll:HLL=None):
        self.scno,self.name,self.status = scno,name,status
        self.hll = hll or HLL()
        self.ts = datetime.now()
    @property
    def interesting(self) -> bool:
        if self.status == FuzzResult.STATUS_CRASH: return True
        if self.status == FuzzResult.STATUS_OK:
            if self.hll.is_minus1() or self.hll.is_zero(): return False
            if self.hll.is_kptr(): return True
            return True
        if self.status in (FuzzResult.STATUS_NOWRAP, FuzzResult.STATUS_RAW):
            return False  # informational, not "interesting"
        return False
    def brief(self) -> str:
        if self.status == FuzzResult.STATUS_OK:
            return f"[{self.scno:03d}] {self.name} = {self.hll}"
        return f"[{self.scno:03d}] {self.name} = {self.status}"
    def key(self) -> tuple:
        return (self.scno, self.name)
    def to_dict(self) -> dict:
        return dict(scno=self.scno, name=self.name, status=self.status,
                    h=self.hll.h, l=self.hll.l, value=str(self.hll),
                    ts=self.ts.isoformat())

# ─── Lua Payload Generator ─────────────────────────────────────
def gen_lua_payload(test_cases: List[Tuple[int, str, List[int]]]) -> str:
    """Generate a single Lua payload testing multiple syscalls.
    test_cases: [(scno, name, [a1..a6]), ...]
    Returns Lua source string.
    """
    lines = ['local wt=syscall.syscall_wrapper','local fc=native.fcall','local fmt=string.format']
    seen_sc: Set[int] = set()
    for scno, name, args in test_cases:
        if scno in seen_sc: continue
        seen_sc.add(scno)
        a = [(f'({x})' if x < 0 else str(x)) if isinstance(x,int) else str(x) for x in args]
        while len(a) < 6: a.append('0')
        a_s = ','.join(a)
        safe = name.replace('|','_').replace('"','')[:40]
        lines.append(
            f'do local w=wt[{scno}]'
            f' if w then local ok,r=pcall(fc,w,{a_s})'
            f'  if ok and type(r)=="table" then'
            f'    print(fmt("R|{scno}|{safe}|O|%d|%d",r.h or 0,r.l or 0))'
            f'  elseif ok then print("R|{scno}|{safe}|R="..tostring(r))'
            f'  else print("R|{scno}|{safe}|C") end'
            f' else print("R|{scno}|{safe}|N") end end'
        )
    return '\n'.join(lines)

def parse_lua_response(resp: str) -> List[FuzzResult]:
    """Parse 'R|' lines from PS4 Lua output."""
    results = []
    for line in resp.split('\n'):
        line = line.strip()
        if not line.startswith('R|'): continue
        parts = line.split('|')
        try:
            scno = int(parts[1])
            name = parts[2]
            status = parts[3]
            h = int(parts[4]) & 0xFFFFFFFF if len(parts) >= 5 and status == 'O' else 0
            l = int(parts[5]) & 0xFFFFFFFF if len(parts) >= 6 and status == 'O' else 0
            results.append(FuzzResult(scno, name, status, HLL(h,l)))
        except (ValueError, IndexError):
            results.append(FuzzResult(0, 'parse_err', FuzzResult.STATUS_RAW))
    return results

# ─── PS4 Connection (Per-send reconnect) ───────────────────────
# PS4 Lua loader closes connection after each script execution.
# Each send() opens a fresh connection.

class PS4Conn:
    def __init__(self, host=PS4_HOST, port=PS4_PORT):
        self.host, self.port = host, port
    
    def _connect(self) -> Optional[socket.socket]:
        """Open + return a fresh socket (or None)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((self.host, self.port))
            return s
        except:
            return None
    
    def send(self, lua: str) -> str:
        """Open connection, send Lua, receive response, close."""
        s = self._connect()
        if not s: return ""
        data = lua.encode('utf-8')
        try:
            s.sendall(struct.pack('<Q', len(data)) + data)
        except:
            try: s.close()
            except: pass
            return ""
        resp = b""
        s.settimeout(5)
        try:
            while True:
                c = s.recv(65536)
                if not c: break
                resp += c
        except socket.timeout:
            pass
        except:
            pass
        try: s.close()
        except: pass
        return resp.decode('utf-8', errors='replace')
    
    def alive(self) -> bool:
        r = self.send('print("[+]");')
        return bool(r and '[+]' in r)
    
    def wait_forever(self, on_wait: Callable = None) -> None:
        """Keep trying until alive-check passes. Returns when PS4 is ready."""
        attempt = 0
        while True:
            if self.alive():
                return
            if on_wait:
                on_wait(attempt)
            attempt += 1
            time.sleep(RETRY_INTERVAL)

# ─── Progress Tracker ──────────────────────────────────────────
class ProgressTracker:
    """Saves/loads fuzzer progress so it can resume after crashes/reboots."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.completed: Set[tuple] = set()   # (scno, name)
        self.results: List[dict] = []
        self.interesting: List[dict] = []
        self.crashes = 0
        self.started = datetime.now().isoformat()
        self.load()
    
    def load(self):
        if not os.path.exists(self.filepath): return
        try:
            with open(self.filepath) as f:
                d = json.load(f)
            self.completed = set(tuple(x) for x in d.get('completed', []))
            self.results = d.get('results', [])
            self.interesting = d.get('interesting', [])
            self.crashes = d.get('crashes', 0)
            self.started = d.get('started', self.started)
        except: pass
    
    def save(self):
        d = dict(
            completed=[list(k) for k in self.completed],
            results=self.results[-5000:],  # keep last 5000
            interesting=self.interesting,
            crashes=self.crashes,
            started=self.started,
            updated=datetime.now().isoformat()
        )
        with open(self.filepath, 'w') as f:
            json.dump(d, f, indent=2)
    
    def add(self, r: FuzzResult):
        key = r.key()
        if key in self.completed: return
        self.completed.add(key)
        self.results.append(r.to_dict())
        if r.interesting:
            self.interesting.append(r.to_dict())
        if r.status == FuzzResult.STATUS_CRASH:
            self.crashes += 1
    
    def is_done(self, scno: int, name: str) -> bool:
        return (scno, name) in self.completed

# ─── Fuzzing Strategies ─────────────────────────────────────────
class Strategies:
    """Each method returns List[Tuple[scno, name, [a1..a6]]]"""
    
    @staticmethod
    def basic() -> list:
        return [(sc, f"z{sc}", [0,0,0,0,0,0]) for sc in range(585, 678)]
    
    @staticmethod
    def buffer() -> list:
        cases = []
        for sc in range(585, 678):
            for sz in [0, 0x10, 0x40, 0x100]:
                cases.append((sc, f"b{sc}_{sz:x}", [0xDEADBEEF, sz, 0,0,0,0]))
        return cases
    
    @staticmethod
    def edge() -> list:
        targets = [585, 586, 595, 600, 602, 606, 609, 614, 617, 620, 621, 624, 638, 657, 675, 676, 677]
        vals = [1, -1, 0xFFFFFFFF, 0xDEAD, 0x1337, 0x539, 0x1000, 0x100000, 0x7FFFFFFF, 0x80000000]
        cases = []
        for sc in targets:
            for v in vals:
                cases.append((sc, f"e{sc}_a1_{v:x}", [v,0,0,0,0,0]))
            for sz in [0, 1, 4, 0x10, 0x40, 0x100, 0x1000]:
                cases.append((sc, f"e{sc}_b{sz:x}", [0xBEEF0000+sz, sz, 0,0,0,0]))
        return cases
    
    @staticmethod
    def exhaustive() -> list:
        patterns = [
            [0,0,0,0,0,0], [1,0,0,0,0,0], [-1,0,0,0,0,0],
            [0xDEADBEEF,0,0,0,0,0], [0xDEADBEEF,0x40,0,0,0,0],
            [0,0xDEADBEEF,0x40,0,0,0], [0,0,0xDEADBEEF,0x40,0,0],
            [0,0,0,0xDEADBEEF,0x40,0], [0,0,0,0,0xDEADBEEF,0x40],
            [0,0,0,0,0,0xDEADBEEF],
        ]
        cases = []
        for sc in range(585, 678):
            for i, pat in enumerate(patterns):
                cases.append((sc, f"x{sc}_p{i}", list(pat)))
        return cases
    
    @staticmethod
    def random() -> list:
        """Seeded random values for all Sony syscalls, multiple iterations."""
        rng = random.Random(0x1352)
        cases = []
        for iteration in range(5):
            for sc in range(585, 678):
                args = [rng.randint(-1, 0xFFFFFFFF) for _ in range(6)]
                cases.append((sc, f"r{sc}_i{iteration}", args))
        return cases
    
    @staticmethod
    def boundary() -> list:
        """Boundary values (power of 2 edges, negative, large)."""
        specials = [0, 1, -1, -2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                    0x100000000, 0xFFFFFFFFFFFF, 0x1000000000000,
                    0x7FFFFFFFFFFFFFFF, 0x8000000000000000]
        cases = []
        for sc in list(range(585, 678)):
            for v in specials:
                cases.append((sc, f"bnd{sc}_{v:x}", [v & 0xFFFFFFFF, 0,0,0,0,0]))
        return cases
    
    @staticmethod
    def mutation(base_cases: list = None, iterations: int = 3) -> list:
        """Mutate existing test cases by flipping bits."""
        if base_cases is None:
            base_cases = Strategies.basic()
        rng = random.Random(0x1352)
        muts = []
        for scno, name, args in base_cases:
            for it in range(iterations):
                new_args = list(args)
                # mutate 1-3 args
                for _ in range(rng.randint(1, 3)):
                    pos = rng.randint(0, 5)
                    mode = rng.choice(['bitflip', 'add', 'mul', 'negate'])
                    val = new_args[pos]
                    if mode == 'bitflip':
                        bit = rng.randint(0, 31)
                        val ^= (1 << bit)
                    elif mode == 'add':
                        val += rng.randint(-1000, 1000)
                    elif mode == 'mul':
                        val = int(val * rng.choice([2, 0, -1, 0x10001]))
                    else:
                        val = ~val
                    new_args[pos] = val
                muts.append((scno, f"m{scno}_{it}", new_args))
        return muts

# ─── External Tool Integration ─────────────────────────────────
class ExtTools:
    """Graceful integration with Kali/System tools (nmap, scapy, etc.)"""
    
    @staticmethod
    def nmap_scan(host=PS4_HOST) -> dict:
        """Run nmap against PS4, return parsed results."""
        result = dict(ports=[], os="", note="")
        try:
            r = subprocess.run(
                ['nmap', '-sS', '-T4', '-p-', '--min-rate', '5000', '-oG', '-', host],
                capture_output=True, text=True, timeout=300
            )
            for line in r.stdout.split('\n'):
                if '/open/' in line:
                    for part in line.strip().split():
                        if '/' in part:
                            p = part.split('/')
                            result['ports'].append(int(p[0]))
            result['note'] = f"Found {len(result['ports'])} open ports"
        except FileNotFoundError:
            result['note'] = "nmap not installed"
        except subprocess.TimeoutExpired:
            result['note'] = "nmap timed out"
        except Exception as e:
            result['note'] = f"nmap error: {e}"
        return result
    
    @staticmethod
    def nmap_quick(host=PS4_HOST) -> dict:
        """Quick check of known PS4 ports (9026 Lua, 9295 Remote Play)."""
        result = dict(ports=[], services={})
        try:
            r = subprocess.run(
                ['nmap', '-sT', '-T4', '--open', '-p', '9026,9295',
                 '-oG', '-', host],
                capture_output=True, text=True, timeout=30
            )
            for line in r.stdout.split('\n'):
                if '/open/' in line:
                    for part in line.strip().split():
                        if '/' in part and 'open' in part:
                            p = part.split('/')[0]
                            result['ports'].append(int(p))
        except: pass
        return result
    
    @staticmethod
    def scapy_send(port: int, data: bytes, host=PS4_HOST) -> str:
        """Send a raw TCP packet using scapy."""
        try:
            import scapy.all as scapy
            ip = scapy.IP(dst=host)
            syn = scapy.TCP(sport=random.randint(1024,65535), dport=port, flags='S')
            resp = scapy.sr1(ip/syn, timeout=5, verbose=0)
            if resp and resp.haslayer(scapy.TCP) and resp.getlayer(scapy.TCP).flags & 0x12:
                return "OPEN"
            return "CLOSED/FILTERED"
        except Exception as e:
            return f"scapy error: {e}"
    
    @staticmethod
    def available() -> dict:
        """Check which tools are available."""
        tools = {}
        for cmd in ['nmap']:
            try:
                subprocess.run([cmd, '--version'], capture_output=True, timeout=5)
                tools[cmd] = True
            except: tools[cmd] = False
        try:
            import scapy
            tools['scapy'] = True
        except: tools['scapy'] = False
        return tools

# ─── Fuzzer Engine ──────────────────────────────────────────────
class FuzzerEngine:
    """Core fuzzer: persistent connection, resume, multi-strategy."""
    
    def __init__(self):
        self.conn = PS4Conn()
        self.running = True
        signal.signal(signal.SIGINT, self._sigint)
        signal.signal(signal.SIGTERM, self._sigint)
        
        # Tool banner
        self._print_banner()
    
    def _print_banner(self):
        tools = ExtTools.available()
        tool_str = ' | '.join(f"{k}={'✔' if v else '✘'}" for k,v in tools.items())
        print(f"""
  ╔══════════════════════════════════════════════╗
  ║   PS4 FW 13.52 Advanced Fuzzer               ║
  ║   Persistent · Resumable · Kali-Integrated   ║
  ╚══════════════════════════════════════════════╝
  Tools: {tool_str}
  Target: {PS4_HOST}:{PS4_PORT}
  Log: {LOG_DIR}
  Retry: every {RETRY_INTERVAL}s (infinite)
        """)
    
    def _sigint(self, signal_num, frame):
        print("\n[!] Shutting down gracefully...")
        self.running = False
    
    def _wait_callback(self, attempt: int):
        """Called during connection retry loops."""
        if not self.running: raise SystemExit()
        if attempt == 0 or attempt % 4 == 0:
            ts = datetime.now().strftime('%H:%M:%S')
            elapsed = attempt * RETRY_INTERVAL
            print(f"  [{ts}] ⏳ Waiting for PS4 ({elapsed}s elapsed)...", flush=True)
    
    def run_strategy(self, strategy_name: str, cases: List[Tuple]) -> List[FuzzResult]:
        """Execute a complete fuzzing strategy with persistence + resume."""
        print(f"\n{'─'*60}")
        print(f"  Strategy: {strategy_name}")
        print(f"  Total cases: {len(cases)}")
        print(f"{'─'*60}\n")
        
        tracker = ProgressTracker(os.path.join(LOG_DIR, f"progress_{strategy_name}.json"))
        
        # Filter out already-completed
        pending = [c for c in cases if not tracker.is_done(c[0], c[1])]
        skipped = len(cases) - len(pending)
        if skipped:
            print(f"  ▶ resumed: {skipped} cases already done")
        
        if not pending:
            print(f"  ✓ All cases completed!")
            return []
        
        # Deduplicate by (scno, name)
        seen: Set[tuple] = set()
        unique = [(c[0], c[1], c[2]) for c in pending if not (c[0], c[1]) in seen and not seen.add((c[0], c[1]))]
        total = len(unique)
        batch_results: List[FuzzResult] = []
        
        # Main fuzzing loop — waits forever for PS4, never gives up
        while unique and self.running:
            print(f"  [connect] waiting for {PS4_HOST}:{PS4_PORT}...", flush=True)
            self.conn.wait_forever(on_wait=self._wait_callback)
            
            print(f"  [✓ connected] {len(unique)} tests remaining")
            
            # Drain batches while PS4 is responsive
            while unique and self.running:
                batch = unique[:BATCH_SIZE]
                unique = unique[BATCH_SIZE:]
                
                payload = gen_lua_payload(batch)
                resp = self.conn.send(payload)
                
                if not resp:
                    tracker.save()
                    print(f"  [!] PS4 crashed — waiting for restart...")
                    break  # back to outer wait loop
                
                results = parse_lua_response(resp)
                for r in results:
                    tracker.add(r)
                    batch_results.append(r)
                    if r.interesting:
                        print(f"    ⚡ {r.brief()}", flush=True)
                
                tracker.save()
                done_total = total - len(unique)
                pct = done_total / total * 100
                print(f"  [{pct:5.1f}%] +{len(results)} done, {len(unique)} left, "
                      f"{tracker.crashes} crashes", flush=True)
                
                time.sleep(BATCH_DELAY)
        
        # Summary
        print(f"\n  {'─'*40}")
        print(f"  Strategy '{strategy_name}' complete:")
        print(f"    Total results: {len(tracker.results)}")
        print(f"    Interesting:   {len(tracker.interesting)}")
        print(f"    Crashes:       {tracker.crashes}")
        if tracker.interesting:
            print(f"    Top findings:")
            for r in tracker.interesting[-20:]:
                scno = r.get('scno','?')
                val = r.get('value','?')
                name = r.get('name','?')
                print(f"      [{scno:03d}] {name} = {val}")
        
        return batch_results

# ─── Strategy Registry ─────────────────────────────────────────
STRATEGY_REGISTRY: Dict[str, Callable] = OrderedDict([
    ('basic',       Strategies.basic),
    ('buffer',      Strategies.buffer),
    ('edge',        Strategies.edge),
    ('exhaustive',  Strategies.exhaustive),
    ('random',      Strategies.random),
    ('boundary',    Strategies.boundary),
    ('mutation',    Strategies.mutation),
])

# ─── Main ──────────────────────────────────────────────────────
def main():
    engine = FuzzerEngine()
    
    # Parse strategies from args (filter out flags)
    all_args = []
    for a in sys.argv[1:]:
        all_args.extend(a.lower().split(','))
    all_args = [a.strip() for a in all_args if a.strip()]
    chosen = [a for a in all_args if not a.startswith('--')] or ['basic']
    
    # --all runs every strategy
    if '--all' in all_args:
        chosen = list(STRATEGY_REGISTRY.keys())
    
    # Optional nmap scan before starting
    if '--scan' in all_args:
        print("\n  [scan] Quick port check...")
        result = ExtTools.nmap_quick()
        if result['ports']:
            print(f"  [scan] Open ports: {result['ports']}")
        else:
            print(f"  [scan] No open ports found")
    
    if '--nmap-full' in all_args:
        print("\n  [scan-full] Full nmap scan (all ports)...")
        result = ExtTools.nmap_scan()
        print(f"  [scan-full] {result.get('note','')}")
        if result.get('ports'):
            for p in sorted(result['ports']):
                print(f"    {p}")
    
    all_results = {}
    for name in chosen:
        if name in STRATEGY_REGISTRY:
            gen_fn = STRATEGY_REGISTRY[name]
            results = engine.run_strategy(name, gen_fn())
            all_results[name] = results
        else:
            print(f"  [!] Unknown strategy '{name}'")
    
    print(f"\n  {'='*50}")
    print(f"  ALL STRATEGIES COMPLETE")
    print(f"  Run: python3 ps4_fuzzer.py {' '.join(sys.argv[1:])}")
    print(f"  Logs: {LOG_DIR}")
    print(f"{'='*50}\n")

if __name__ == '__main__':
    main()
