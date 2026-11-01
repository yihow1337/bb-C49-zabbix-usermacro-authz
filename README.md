# Zabbix 7.4.16 / 7.0.32 — usermacro.get authorization bypass via missing ugsetid filter (host macro disclosure)

**Program:** Zabbix (HackerOne)  
**Asset:** Zabbix Server / Frontend API (`api_jsonrpc.php`) — method `usermacro.get`  
**Affected (verified):** 7.4.16 (latest 7.4 stable), 7.0.32 (latest 7.0 LTS)  
**Fixed (unreleased):** `release/7.4` commit `3bdf6c3ec5` / merge `cbf8984bed` (DEV-4859); `release/7.0` `70b09731b0`  
**CWE:** CWE-863 Incorrect Authorization  
**CVSS 3.1 (conservative):** 6.5 Medium — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`  
(Confidentiality High when macros hold secrets; reduce to C:L / ~4.3 if program rates generic config disclosure lower.)

## Summary
`usermacro.get` for non-super-admin users joins the `permission` table on host-group set (`hgsetid`) **without** constraining `permission.ugsetid` to the caller’s user-group set. Any other ugset’s permission row for that host group satisfies the join, so a low-privilege authenticated user can read host/template macros belonging to hosts they are not authorized to access. Sibling API `host.get` correctly filters `p.ugsetid`.

## Vulnerable code (7.4.16)

File: `ui/include/classes/api/services/CUserMacro.php` (tag `6077373a10ff55772f566646244e2b0cb562ef2e`)

```php
$sqlParts['from'][] = 'host_hgset hh';
$sqlParts['from'][] = 'permission p';
$sqlParts['where'][] = 'hm.hostid=hh.hostid';
$sqlParts['where'][] = 'hh.hgsetid=p.hgsetid';
// MISSING: $sqlParts['where'][] = 'p.ugsetid='.self::$userData['ugsetid'];
if ($options['editable']) {
    $sqlParts['where'][] = 'p.permission='.PERM_READ_WRITE;
}
```

## Fix (unreleased on release/7.4)

```php
$sqlParts['where'][] = 'hh.hgsetid=p.hgsetid';
$sqlParts['where'][] = 'p.ugsetid='.self::$userData['ugsetid'];
```

Vendor also added `ui/tests/api_json/testUserMacroPermissions.php` covering cross-host denial cases.

## Prerequisites
- Valid Zabbix user session / API auth (User or Admin type).
- Caller must have `ugsetid != 0` (member of at least one user group). Users with no groups already hit the early empty return.
- Role must allow `usermacro.get` (default: allowed for any user type unless revoked).
- At least one other ugset in the system must have a `permission` row for the target host’s hgset (normal multi-team deployments).

## Reproduction (harmless / synthetic)

### A. Logic PoC (no server required)
```bash
python3 poc_usermacro_authz.py
```
Expected: vulnerable JOIN returns unauthorized host2 macros (`{$API_TOKEN}=tok-host2-LEAK`); fixed JOIN does not. All checks PASS.

### B. Live API (authorized lab instance only — synthetic macros)
1. Install Zabbix 7.4.16 from official tarball (`sha256` in evidence).
2. Create host groups G1/G2, hosts H1/H2, macros `{$UM1}` on H1 and `{$SECRET}` on H2.
3. User group UG1 → RW on G1 only; user U1 in UG1 with API access.
4. As U1:
```json
{"jsonrpc":"2.0","method":"usermacro.get","params":{"output":["hostmacroid","hostid","macro","value"]},"auth":"<token>","id":1}
```
5. **Actual (vulnerable):** response includes H2’s `{$SECRET}`.  
   **Expected:** only H1 macros.
6. Apply DEV-4859 patch / build from `release/7.4` tip → retest → H2 macros absent.

## Negative controls
- Same caller against fixed SQL / patched build → no cross-host macros.
- User with zero user groups (`ugsetid=0`) → empty result even on vulnerable build.
- `host.get` for the same user does **not** list H2 (correct ugsetid filter) while `usermacro.get` does — demonstrates the inconsistency.

## Impact
Confidentiality loss of host/template macro values across authorization boundaries. In production these macros frequently store credentials used by items, scripts, integrations, and vault references. No integrity/availability impact by itself. Not unauthenticated.

## Distinctness
Not a duplicate of trapper/command-result issues (e.g. DEV-5052), host.get PSK (CVE-2026-23937), hostprototype.get (CVE-2025-27238), or user.get search (CVE-2025-27236). Unique sink: `CUserMacro` permission JOIN.

## Remediation
Ship DEV-4859 to 7.4.x / 7.0.x stable tags; ensure all `permission` joins include `ugsetid` (repo scan showed only this service missed it at 7.4.16).

## Payout expectation (realistic)
HackerOne Zabbix historical Medium API authz / info-disclosure band — roughly **$300–$1,000** depending on triage’s macro-secret weighting; could trend higher if they accept C:H.

## Submission status
**NOT SUBMITTED.** Evidence package ready. Awaiting explicit user approval before any HackerOne report.
