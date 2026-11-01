# C49 Round 17 — Zabbix usermacro.get missing ugsetid (DEV-4859)

## Fingerprint
`Zabbix | CUserMacro::get (API usermacro.get) | api_jsonrpc.php usermacro.get | SQL JOIN permission on hgsetid only | missing p.ugsetid=caller filter | CWE-863 | host-macro secret disclosure across unauthorized hosts | authenticated user with ugsetid!=0 (member of ≥1 user group)`

## Versions
- Vulnerable released: **7.4.16** (tag `6077373a10ff55772f566646244e2b0cb562ef2e`), also **7.0.32** (same missing filter).
- Official source tarball: https://cdn.zabbix.com/zabbix/sources/stable/7.4/zabbix-7.4.16.tar.gz
  sha256: `0e2c391dc184acce8e34250e7326a51e19c8bcee31e67b8497f5526247ecd261`
- Fix on `origin/release/7.4` (NOT in any 7.4.x tag yet): leaf `3bdf6c3ec5d3edf77fd971b424c2ae7b41424f6d`, merge `cbf8984bed9076f83f081c96552ee961ce2523f8` (DEV-4859, 2026-10-20/26).
- Fix also on `origin/release/7.0` (70b09731b0) — not in 7.0.32 tag.

## Root cause
In `ui/include/classes/api/services/CUserMacro.php` permission check for non-super-admin:
joins `host_hgset` + `permission` on `hgsetid` but **omits** `p.ugsetid = self::$userData['ugsetid']`.
Sibling API `CHost::get` correctly includes the ugsetid predicate. Repo-wide scan at 7.4.16: **only CUserMacro.php** has this omission among hgsetid permission joins.

## Impact
Any authenticated user belonging to ≥1 user group can read **host/template macros** for every host whose hgset appears in the `permission` table for *any* ugset (i.e., essentially all hosts that anyone can access). Host macros commonly store credentials (`{$PASSWORD}`, API tokens, SNMP communities, vault paths).

## Novelty / duplicate search (2026-11-01 Asia/Taipei)
- No CVE/GHSA/advisory for usermacro.get / DEV-4859 / "ugsetid" macro.
- Nearby public Zabbix CVEs are distinct: CVE-2025-27236 (user.get search), CVE-2025-27238 (hostprototype.get), CVE-2026-23925 (configuration.import), CVE-2026-23937 (host.get PSK).
- Not in prior ledger (C30 was trapper DEV-5052 command-result hostid check).
- Vendor ticket DEV-4859 private; fix landed silently on release branches without a Security-section blog entry yet.

## PoC
`poc_usermacro_authz.py` — SQLite reimplementation of the exact JOIN; synthetic macros only.
All 6 checks PASS (see poc-output.txt). Vendor regression `testUserMacroPermissions.php` packaged as supporting evidence of intended authz.

## Negative controls
- Fixed query with ugsetid filter → only authorized host macros.
- ugsetid==0 → empty (matches early-return in vulnerable code).

## Scope
Zabbix HackerOne public bug bounty — API/Frontend of supported releases. Paid program (HTTP 200). Do **not** submit without user approval.
