#!/bin/bash
# Stage the sc#434/sc#435 probe chain ready for the NEXT clean boot.
# Two syscalls remain unprobed in the Sony-custom range 585-677; they are the
# only entries left in the entire syscall map. Run this while PS4 is OFF so
# the chain_*.js is current; then on fresh boot serve it and hit
#   http://192.168.100.61:8080/sb588l.html?probe=434-435
# Devkit-only markers are NOT expected to open anything from uid=1, but Sony
# customs are the one surface that has varied per-FW; 434/435 are unverified.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC=poc/chain_sb588k.js
DST=poc/chain_sb588l.js
if [ ! -f "$SRC" ]; then echo "ERROR: $SRC missing"; exit 1; fi
cp -f "$SRC" "$DST"
# Tag the probe URL parameter so scene_monitor can tell this is 434/435
grep -q "probe=434-435" "$DST" || sed -i "s|const params = new URLSearchParams|// sc#434/435 probe staged for next clean boot\nconst params = new URLSearchParams|" "$DST"
sed -i "s|probe=verbatim|probe=434-435|g" "$DST"
cat >> "$DST" <<'CHAIN'
// === sc#434/435 PROBE (staged, needs clean boot) ===
// Sony customs: only remaining unprobed syscall numbers in 585-677 range.
// Semantics unknown; probe with several arg shapes. Sony custom ucred/UAF
// primitives are all dead (Poopsploit requires BD-J); 434/435 are the sole
// unknowns. Sandbox blocks fork/setuid families; probing is uid=1 only.
report("PROBE434", "staged for next clean boot");
try {
  const sc434 = native.fcall(0x434, 0, 0, 0, 0, 0, 0);
  report("SC434", "rv=" + sc434);
} catch (e) { report("SC434-ERR", String(e)); }
try {
  const sc435 = native.fcall(0x435, 0, 0, 0, 0, 0, 0);
  report("SC435", "rv=" + sc435);
} catch (e) { report("SC435-ERR", String(e)); }
CHAIN
echo "staged: $DST ($(wc -c < "$DST") bytes)"
