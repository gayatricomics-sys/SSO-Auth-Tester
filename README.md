# Auth / SSO / OAuth / SAML / WSTG Tester (Burp Suite Extension)

A comprehensive Jython 2.7 extension for Burp Suite designed to automate data extraction via proxy traffic auto-population and assist with security analysis for **OAuth 2.0 / OIDC**, **SAML 2.0**, **OWASP WSTG** (Password Management, Authentication, Authorization), and **WAF Bypass**.

---

## 🌟 Key Features

### 1. ⚡ Native Burp Scanner Integration (`IScannerCheck`)
- **Passive Scanner Integration**: Automatically runs passive checks on all traffic going through Burp Suite (Proxy, Repeater, Scanner, Spider).
- **Active Scanner Integration**: Automatically performs active vulnerability probes when running Active Scans in Burp Suite.
- **Official Burp Dashboard & Target Issue Activity**: Reports findings directly into Burp Suite's native **Dashboard**, **Target -> Issue Activity**, and **Scanner** tab views as native `IScanIssue` items.

### 2. ⚡ Real-Time Proxy Interception & Universal Auto-Population
- **Case-Insensitive Traffic Parsing**: Dynamically extracts parameters across URL query strings, URL-encoded POST bodies, JSON payloads, and HTTP headers (`Authorization: Bearer`, `Cookie`, etc.).
- **Clean Field Initialization**: Starts with clean, empty fields without hardcoded placeholder text, ensuring an uncluttered workspace across all projects.
- **Robust Silent Error Handling & Diagnostic Output**: Prevents Java exceptions and Burp error popups. Live traffic logs print directly to Burp's Extender Output window (`[AuthSSO Traffic] ...`).
- **WAF Bypass Queue**: Auto-captures blocked HTTP response status codes (`403 Forbidden`, `406`, `429 Rate-Limited`).

### 3. 🛡️ Comprehensive Security Test Generators
- **OAuth 2.0 / OIDC**:
  - `redirect_uri` validation checks (Subdomains, `@` userinfo trick, path traversal, double encoding `%252f`, HTTP downgrade).
  - `response_type` tampering (Implicit flow `token`, Hybrid flow `code id_token token`, `response_type=none`).
  - PKCE enforcement & downgrade (`code_challenge` omitted, `code_challenge_method=plain`).
  - State parameter omission (Login CSRF) & Scope escalation checks.
- **Microsoft Entra ID & ADFS**:
  - Tenant confusion (`/common/`, `/consumers/`), missing `nonce`, silent authentication (`prompt=none`), token fragment leakage, `/adminconsent` scope review.
  - WS-Federation `wreply` host mismatch, `wtrealm` party swapping, and `wctx` reflected parameter checks.
- **SAML 2.0**:
  - Signature stripping, `SignatureValue` blanking, `NameID` tampering.
  - XML Signature Wrapping (**XSW-1** & **XSW-2** assertion cloning).
  - SAML comment injection (`admin<!--comment-->@target.com`), `AudienceRestriction` & `Recipient` URL swapping, XXE DTD probing templates.
- **OWASP WSTG (Password Management, Auth & AuthZ)**:
  - **WSTG-ATHN-01**: Unencrypted HTTP channel detection.
  - **WSTG-ATHN-04**: Header-based authentication bypass (`X-Forwarded-User`, `X-Remote-User`, `X-Original-URL`, `X-User-Id`, `X-Role`).
  - **WSTG-ATHN-06**: Browser cache control header checks (`Cache-Control: no-store`, `Pragma: no-cache`).
  - **WSTG-ATHN-07**: Password complexity policy checker.
  - **WSTG-ATHN-08**: Password reset token disclosure in response bodies.
  - **WSTG-ATHZ-02 / 03 / 04**: Administrative path direct access, privilege escalation via role parameter tampering (`role=admin`, `is_admin=true`), and IDOR parameter increment probes.

---

## 🧪 Advanced Passive & Active SSO Checks

The extension performs the following security checks automatically as traffic passes through Burp or during Active/Passive scans:

- **Microsoft Entra ID / Identity Platform tokens**
  - Issuer, tenant (`tid`), audience (`aud`), expiry (`exp`), `nbf`, `iat`, `kid`, and token-version sanity.
  - App-only/service-principal confusion using `idtyp` and `appidacr`.
  - `roles`, `scp`, `azp`/`appid`, MFA/authentication-context claims, and Graph/custom-API audience confusion.
- **OAuth 2.0 / OIDC authorization requests**
  - Missing `state`, missing or weak PKCE, implicit/hybrid flows, missing `nonce`, weak redirect URI patterns, HTTP downgrade, wildcard/userinfo/traversal tricks, and Microsoft multi-tenant endpoint exposure.
- **SAML 2.0**
  - Response/assertion signature coverage, missing audience/recipient constraints, HTTP recipients, lifetime issues, duplicate assertion IDs, missing issuer, comment/XXE markers, and missing `InResponseTo`.
- **SSO session controls**
  - `Cache-Control`, HSTS, `X-Content-Type-Options`, and cookie `Secure`/`HttpOnly`/`SameSite` flags.

Findings appear in both the extension's **Results** tab and Burp Suite's official **Target / Dashboard Issue Activity** list.

---

## 🚀 Installation & Setup

1. **Prerequisite (Jython Standalone):**
   - Ensure you have `jython-standalone-2.7.3.jar`.

2. **Configure Burp Suite:**
   - Go to **Extensions** $\rightarrow$ **Options** (or **Extender** $\rightarrow$ **Options**).
   - Under **Python Environment**, click **Select file...** and point it to your `jython-standalone-2.7.3.jar`.

3. **Load the Extension:**
   - Go to **Extensions** $\rightarrow$ **Installed** (or **Extender** $\rightarrow$ **Extensions**).
   - Click **Add**.
   - Set **Extension type** to **Python**.
   - Select `auth_sso_tester.py`.
   - Click **Next**. A new tab named **"Auth/SSO/WSTG Tester"** will appear in Burp Suite.

---

## 📊 Workflow & Usage

1. **Proxy & Scanner Integration**: Turn on Burp Proxy, browse your target web application, or launch a scan. All fields across the extension GUI will automatically populate, and scanner issues will populate in Burp's Dashboard & Target tab.
2. **Generate Test Variants**: Click the module buttons on any tab (OAuth, SAML, WSTG, WAF Bypass) to generate test variants directly into Burp Repeater.
3. **Review & Report**: View captured findings in the **Results** tab and export a structured Markdown report (`auth_sso_wstg_test_report.md`).

---

## 🔒 License & Disclaimer

This extension is provided for authorized security assessments and penetration testing engagements only. Always ensure you have explicit authorization before performing testing against target systems.
