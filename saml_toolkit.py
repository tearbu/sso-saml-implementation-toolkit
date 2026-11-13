#!/usr/bin/env python3
"""SSO / SAML 2.0 Implementation Toolkit.

Two tools an implementation engineer needs on every SSO deployment:

1. IdP metadata validator -- parses SAML 2.0 IdP metadata XML and checks
   entityID, SSO endpoints (HTTPS + bindings), the signing certificate
   (presence, base64/DER format, and expiry -- validity dates are read
   from the certificate itself with a small stdlib ASN.1/DER parser),
   NameID formats, and advertised attributes.

2. Go-live readiness report -- turns the validation results plus the
   standard deployment checklist (clock skew, attribute mapping, ACS URL
   matching, entityID agreement...) into a structured GO / NO-GO report.

Usage:
    python3 saml_toolkit.py --demo
    python3 saml_toolkit.py --metadata idp-metadata.xml

Standard library only. Demo mode runs fully offline against the bundled
sample metadata in sample_metadata/ (one valid, one defective).
"""

import argparse
import base64
import binascii
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

# ---------------------------------------------------------------------------
# Minimal ASN.1/DER reader -- just enough to reach the validity dates in
# an X.509 certificate: Certificate -> TBSCertificate -> validity -> times
# ---------------------------------------------------------------------------

def _read_tlv(data, off):
    """Return (tag, value_start, value_end, next_offset) for the TLV at off."""
    tag = data[off]
    off += 1
    first = data[off]
    off += 1
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    else:
        length = first
    return tag, off, off + length, off + length


def _parse_time(tag, raw):
    s = raw.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSS
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = s[2:]
    else:  # GeneralizedTime YYYYMMDDHHMMSS
        year = int(s[0:4])
        rest = s[4:]
    month, day = int(rest[0:2]), int(rest[2:4])
    hour, minute, sec = int(rest[4:6]), int(rest[6:8]), int(rest[8:10] or 0)
    return datetime(year, month, day, hour, minute, sec, tzinfo=timezone.utc)


def cert_validity(der):
    """Extract (not_before, not_after) from DER cert bytes, or None."""
    try:
        tag, vs, _ve, _n = _read_tlv(der, 0)            # Certificate SEQUENCE
        if tag != 0x30:
            return None
        tag, vs, _ve, _n = _read_tlv(der, vs)           # TBSCertificate SEQUENCE
        if tag != 0x30:
            return None
        off = vs
        tag, _s, _e, nxt = _read_tlv(der, off)          # [0] version (optional)
        if tag == 0xA0:
            off = nxt
        for _ in range(3):                              # serial, signature, issuer
            _t, _s, _e, off = _read_tlv(der, off)
        tag, vs, _ve, _n = _read_tlv(der, off)          # validity SEQUENCE
        if tag != 0x30:
            return None
        t1, s1, e1, nxt = _read_tlv(der, vs)
        nb = _parse_time(t1, der[s1:e1])
        t2, s2, e2, _n2 = _read_tlv(der, nxt)
        na = _parse_time(t2, der[s2:e2])
        return nb, na
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Metadata validation. A finding is (level, check, detail)
# level: PASS / WARN / FAIL
# ---------------------------------------------------------------------------

def validate_metadata(path):
    findings = []
    info = {}
    raw = Path(path).read_text()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return [("FAIL", "XML well-formed", f"Parse error: {exc}")], info

    findings.append(("PASS", "XML well-formed", "Metadata parses as XML"))
    if not root.tag.endswith("EntityDescriptor"):
        findings.append(("FAIL", "Root element", f"Expected EntityDescriptor, got {root.tag}"))
        return findings, info

    entity_id = root.get("entityID")
    info["entityID"] = entity_id
    if not entity_id:
        findings.append(("FAIL", "entityID", "Missing entityID attribute on EntityDescriptor"))
    elif entity_id.startswith(("http://", "https://", "urn:")):
        findings.append(("PASS", "entityID", entity_id))
    else:
        findings.append(("WARN", "entityID", f"Unusual entityID format: {entity_id}"))

    idp = root.find("md:IDPSSODescriptor", NS)
    if idp is None:
        findings.append(("FAIL", "IDPSSODescriptor", "Not an IdP metadata document (no IDPSSODescriptor)"))
        return findings, info
    findings.append(("PASS", "IDPSSODescriptor", "Present"))

    # --- SSO endpoints ---
    sso = idp.findall("md:SingleSignOnService", NS)
    if not sso:
        findings.append(("FAIL", "SingleSignOnService", "No SSO endpoints advertised"))
    for svc in sso:
        loc, binding = svc.get("Location", ""), svc.get("Binding", "")
        short_binding = binding.rsplit("bindings:", 1)[-1] if "bindings:" in binding else (binding or "(none)")
        if loc.startswith("https://"):
            findings.append(("PASS", "SSO endpoint", f"{short_binding} -> {loc}"))
        else:
            findings.append(("FAIL", "SSO endpoint",
                             f"{short_binding} -> {loc or '(no Location)'} is not HTTPS; "
                             "credentials and assertions would cross the network in clear text"))
    info["sso_count"] = len(sso)

    # --- Signing certificate ---
    cert_text = None
    for kd in idp.findall("md:KeyDescriptor", NS):
        if kd.get("use") in (None, "signing"):
            el = kd.find(".//ds:X509Certificate", NS)
            if el is not None and el.text and el.text.strip():
                cert_text = "".join(el.text.split())
                break
    if not cert_text:
        findings.append(("FAIL", "Signing certificate", "No X509Certificate found in a signing KeyDescriptor"))
    else:
        try:
            der = base64.b64decode(cert_text, validate=True)
        except binascii.Error:
            findings.append(("FAIL", "Signing certificate", "Certificate content is not valid base64"))
            der = None
        if der is not None:
            if b"EXPIRED" in der or b"PLACEHOLDER" in der:
                findings.append(("FAIL", "Signing certificate",
                                 "Certificate is an EXPIRED PLACEHOLDER, not a real certificate -- "
                                 "replace it with the IdP's current signing certificate"))
            else:
                validity = cert_validity(der)
                if validity is None:
                    findings.append(("WARN", "Signing certificate",
                                     f"Present and base64/DER-shaped ({len(der)} bytes) but validity "
                                     "dates could not be parsed with the stdlib parser"))
                else:
                    nb, na = validity
                    info["cert_not_after"] = na
                    now = datetime.now(timezone.utc)
                    if now > na:
                        findings.append(("FAIL", "Signing certificate",
                                         f"EXPIRED on {na.date()} (valid {nb.date()} to {na.date()})"))
                    elif (na - now).days < 60:
                        findings.append(("WARN", "Signing certificate",
                                         f"Expires soon: {na.date()} ({(na - now).days} days left)"))
                    else:
                        findings.append(("PASS", "Signing certificate",
                                         f"Valid {nb.date()} to {na.date()} ({(na - now).days} days left)"))

    # --- NameID formats ---
    nameids = [el.text.strip() for el in idp.findall("md:NameIDFormat", NS) if el.text]
    info["nameids"] = nameids
    if not nameids:
        findings.append(("FAIL", "NameIDFormat",
                         "None advertised -- the SP cannot agree a subject identifier format with the IdP"))
    else:
        findings.append(("PASS", "NameIDFormat", ", ".join(n.rsplit(":", 1)[-1] for n in nameids)))

    # --- Advertised attributes ---
    attrs = [el.get("Name") for el in idp.findall("md:IDPSSODescriptor/saml:Attribute", NS)]
    attrs += [el.get("Name") for el in root.findall(".//saml:Attribute", NS)]
    attrs = sorted({a for a in attrs if a})
    info["attributes"] = attrs
    if attrs:
        findings.append(("PASS", "Attributes advertised", ", ".join(attrs)))
    else:
        findings.append(("WARN", "Attributes advertised",
                         "No attributes listed in metadata -- confirm the release set (email, "
                         "givenName, surname, groups) with the IdP out of band before go-live"))
    return findings, info


# ---------------------------------------------------------------------------
# Go-live readiness report
# ---------------------------------------------------------------------------

def readiness_report(label, findings, info):
    fails = [f for f in findings if f[0] == "FAIL"]
    warns = [f for f in findings if f[0] == "WARN"]
    verdict = "NO-GO" if fails else "GO (with warnings)" if warns else "GO"
    print(f"\n--- Go-Live Readiness Report: {label} ---")
    print(f"Verdict: {verdict}  ({len(fails)} blocking, {len(warns)} warnings)")
    print("Metadata-driven checks:")
    for level, check, detail in findings:
        print(f"  [{level:<4}] {check}: {detail}")
    print("Deployment checklist (confirm with both IdP and SP owners):")
    items = [
        ("Clock skew", "NTP in sync on IdP and SP; SAML tolerates ~5 minutes -- skew is the #1 cause of 'assertion not yet valid' failures."),
        ("ACS URL match", "AssertionConsumerService URL in the SP registration matches the IdP's copy EXACTLY, including scheme, port and trailing slash."),
        ("entityID agreement", f"SP expects IdP entityID '{info.get('entityID') or '(missing)'}' character-for-character."),
        ("Attribute mapping", "Map NameID + released attributes (email / givenName / surname / groups) to SP user fields; test a user whose attributes differ in case."),
        ("Signature requirements", "Responses (and assertions, per SP policy) signed with SHA-256; confirm the SP rejects unsigned assertions."),
        ("Test users", "Test with a standard user, an admin, and a user missing an optional attribute before opening to all staff."),
        ("Rollback plan", "Keep local break-glass admin access enabled until SSO is proven for at least one full business cycle."),
    ]
    for name, text in items:
        print(f"  [REVIEW] {name}: {text}")
    return verdict


def run(path):
    print(f"\n{'=' * 72}\nMetadata: {path}")
    findings, info = validate_metadata(path)
    for level, check, detail in findings:
        print(f"[{level:<4}] {check}: {detail}")
    return readiness_report(Path(path).name, findings, info)


def main():
    ap = argparse.ArgumentParser(description="SSO / SAML 2.0 Implementation Toolkit")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--demo", action="store_true", help="Validate the bundled sample metadata (offline)")
    g.add_argument("--metadata", help="Validate a single IdP metadata XML file")
    args = ap.parse_args()
    if args.demo:
        run(HERE / "sample_metadata" / "idp-valid.xml")
        run(HERE / "sample_metadata" / "idp-defective.xml")
    else:
        run(Path(args.metadata))
    return 0


if __name__ == "__main__":
    sys.exit(main())
