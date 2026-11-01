#!/usr/bin/env python3
"""
Deterministic PoC for Zabbix 7.4.16 usermacro.get missing ugsetid filter (DEV-4859 / C49).

Reproduces the SQL permission join used by CUserMacro::get() for non-super-admin users:
  FROM hostmacro hm
  JOIN host_hgset hh ON hm.hostid = hh.hostid
  JOIN permission p  ON hh.hgsetid = p.hgsetid
  [-- VULN: no p.ugsetid = <caller ugsetid> --]
  [-- FIX:  AND p.ugsetid = <caller ugsetid> --]

Synthetic data only. No network. No real Zabbix instance required.
Negative controls: fixed query; ugsetid==0 early-deny; super-admin path not modeled as bypass.
"""
from __future__ import annotations

import hashlib
import sqlite3
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "poc-output.txt"

# Permission constants mirror Zabbix include/common/defines
PERM_READ = 2
PERM_READ_WRITE = 3

SCHEMA = """
CREATE TABLE hostmacro (
  hostmacroid INTEGER PRIMARY KEY,
  hostid INTEGER NOT NULL,
  macro TEXT NOT NULL,
  value TEXT NOT NULL
);
CREATE TABLE host_hgset (
  hostid INTEGER NOT NULL,
  hgsetid INTEGER NOT NULL
);
CREATE TABLE permission (
  ugsetid INTEGER NOT NULL,
  hgsetid INTEGER NOT NULL,
  permission INTEGER NOT NULL
);
"""

# Scenario (mirrors vendor testUserMacroPermissions.php intent):
# - Host1 in HG1 with secret macro {$DB_PASSWORD}=s3cret-host1  (caller HAS access via ugset=10)
# - Host2 in HG2 with secret macro {$API_TOKEN}=tok-host2-LEAK   (caller has NO access; only ugset=20 does)
# - Caller ugsetid=10
SEED = [
    # hostmacro
    ("INSERT INTO hostmacro VALUES (1, 101, '{$DB_PASSWORD}', 's3cret-host1')",),
    ("INSERT INTO hostmacro VALUES (2, 102, '{$API_TOKEN}', 'tok-host2-LEAK')",),
    ("INSERT INTO hostmacro VALUES (3, 102, '{$SNMP_COMMUNITY}', 'private-leak')",),
    # host_hgset
    ("INSERT INTO host_hgset VALUES (101, 1001)",),
    ("INSERT INTO host_hgset VALUES (102, 1002)",),
    # permission: ugset 10 -> HG1 only; ugset 20 -> HG2 only
    ("INSERT INTO permission VALUES (10, 1001, 3)",),  # caller RW on host1
    ("INSERT INTO permission VALUES (20, 1002, 3)",),  # other group RW on host2
]


def run_query(conn: sqlite3.Connection, caller_ugsetid: int, fixed: bool) -> list[tuple]:
    """Return (hostmacroid, hostid, macro, value) rows visible to caller."""
    if caller_ugsetid == 0:
        return []  # mirrors early return in CUserMacro.php
    sql = """
        SELECT hm.hostmacroid, hm.hostid, hm.macro, hm.value
        FROM hostmacro hm
        JOIN host_hgset hh ON hm.hostid = hh.hostid
        JOIN permission p ON hh.hgsetid = p.hgsetid
        WHERE 1=1
    """
    params: list = []
    if fixed:
        sql += " AND p.ugsetid = ?"
        params.append(caller_ugsetid)
    # else: VULNERABLE — any matching hgsetid permission row grants visibility
    cur = conn.execute(sql, params)
    return list(cur.fetchall())


def main() -> int:
    lines: list[str] = []
    def log(s: str = "") -> None:
        lines.append(s)
        print(s)

    log("=== C49 PoC: Zabbix usermacro.get missing ugsetid filter ===")
    log("Target release: 7.4.16 (tag 6077373a10ff55772f566646244e2b0cb562ef2e)")
    log("Fix (unreleased on release/7.4): 3bdf6c3ec5 / merge cbf8984bed (DEV-4859)")
    log("")

    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    for (stmt,) in SEED:
        conn.execute(stmt)
    conn.commit()

    caller = 10
    vuln_rows = run_query(conn, caller, fixed=False)
    fixed_rows = run_query(conn, caller, fixed=True)
    zero_rows = run_query(conn, 0, fixed=False)

    log("--- VULNERABLE query (7.4.16, no p.ugsetid filter) as ugsetid=10 ---")
    for r in vuln_rows:
        log(f"  VISIBLE: hostmacroid={r[0]} hostid={r[1]} {r[2]}={r[3]}")
    log(f"  count={len(vuln_rows)}")

    log("--- FIXED query (DEV-4859, with p.ugsetid=caller) as ugsetid=10 ---")
    for r in fixed_rows:
        log(f"  VISIBLE: hostmacroid={r[0]} hostid={r[1]} {r[2]}={r[3]}")
    log(f"  count={len(fixed_rows)}")

    log("--- NEGATIVE: ugsetid=0 early-deny (both paths) ---")
    log(f"  count={len(zero_rows)} (expect 0)")

    # Assertions
    leaked = [r for r in vuln_rows if r[1] == 102]
    allowed = [r for r in vuln_rows if r[1] == 101]
    fixed_leak = [r for r in fixed_rows if r[1] == 102]
    fixed_ok = [r for r in fixed_rows if r[1] == 101]

    ok = True
    def check(name: str, cond: bool) -> None:
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        log(f"[{status}] {name}")

    log("")
    log("--- Checks ---")
    check("vuln sees authorized host1 macros", len(allowed) == 1)
    check("vuln LEAKS unauthorized host2 macros", len(leaked) == 2)
    check("leak includes {$API_TOKEN}", any(r[2] == "{$API_TOKEN}" and r[3] == "tok-host2-LEAK" for r in leaked))
    check("fixed keeps host1", len(fixed_ok) == 1)
    check("fixed blocks host2", len(fixed_leak) == 0)
    check("ugsetid=0 returns empty", len(zero_rows) == 0)

    # Integrity over evidence inputs
    vuln_snip = Path(__file__).resolve().parent / "vuln_snippet.php"
    fix_snip = Path(__file__).resolve().parent / "fix_snippet.php"
    for p in (vuln_snip, fix_snip):
        if p.exists():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            log(f"sha256 {p.name} = {h}")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"Wrote {OUT}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
