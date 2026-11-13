# SSO / SAML 2.0 Implementation Toolkit

The two tools an implementation engineer reaches for on every SSO
deployment: a **SAML 2.0 IdP metadata validator** and a **go-live
readiness report generator**.

## The problem it solves

SSO integrations fail late and embarrassingly, usually for preventable
reasons discovered in the go-live call: the IdP's signing certificate
expired last month, the SSO endpoint is still the HTTP test URL, the
metadata advertises no NameID format, the ACS URL registered at the IdP
differs from the SP's by a trailing slash, or the two servers' clocks
are six minutes apart and every assertion is "not yet valid". This
toolkit catches the metadata defects automatically — before the call —
and turns the rest into a structured GO / NO-GO readiness report.

## What the validator checks

- XML well-formedness and `EntityDescriptor` root
- `entityID` presence and format
- SSO endpoints: at least one present, binding recorded, **HTTPS
  enforced** (a plain-HTTP endpoint is a blocking failure)
- Signing certificate: presence in a signing `KeyDescriptor`, valid
  base64, and **expiry read from the certificate itself** — validity
  dates are extracted with a small standard-library ASN.1/DER parser
  (Certificate → TBSCertificate → validity), not guessed from filenames
- `NameIDFormat` values advertised
- Attributes advertised for release (email, givenName, surname, groups…)

The readiness report combines the validation result with the standard
deployment checklist — clock skew, exact ACS URL matching, entityID
agreement, attribute mapping, signature requirements, test users, and a
rollback plan — and issues a **GO / GO with warnings / NO-GO** verdict.

## How to run

```bash
# Demo mode — fully offline, validates both bundled samples and
# generates a readiness report for each
python3 saml_toolkit.py --demo

# Validate a real IdP metadata file from your deployment
python3 saml_toolkit.py --metadata idp-metadata.xml
```

Python 3, standard library only.

## Demo output (actual run)

The valid sample passes everything — note the certificate dates, read
from the embedded certificate by the DER parser:

```
========================================================================
Metadata: sample_metadata/idp-valid.xml
[PASS] XML well-formed: Metadata parses as XML
[PASS] entityID: https://idp.contoso-example.com/saml2
[PASS] IDPSSODescriptor: Present
[PASS] SSO endpoint: HTTP-Redirect -> https://idp.contoso-example.com/saml2/sso/redirect
[PASS] SSO endpoint: HTTP-POST -> https://idp.contoso-example.com/saml2/sso/post
[PASS] Signing certificate: Valid 2026-11-13 to 2027-11-13 (364 days left)
[PASS] NameIDFormat: emailAddress, persistent
[PASS] Attributes advertised: email, givenName, groups, surname

--- Go-Live Readiness Report: idp-valid.xml ---
Verdict: GO  (0 blocking, 0 warnings)
Deployment checklist (confirm with both IdP and SP owners):
  [REVIEW] Clock skew: NTP in sync on IdP and SP; SAML tolerates ~5 minutes -- skew is the #1 cause of 'assertion not yet valid' failures.
  [REVIEW] ACS URL match: AssertionConsumerService URL in the SP registration matches the IdP's copy EXACTLY, including scheme, port and trailing slash.
  [REVIEW] entityID agreement: SP expects IdP entityID 'https://idp.contoso-example.com/saml2' character-for-character.
  [REVIEW] Attribute mapping: Map NameID + released attributes (email / givenName / surname / groups) to SP user fields; test a user whose attributes differ in case.
  [REVIEW] Signature requirements: Responses (and assertions, per SP policy) signed with SHA-256; confirm the SP rejects unsigned assertions.
  [REVIEW] Test users: Test with a standard user, an admin, and a user missing an optional attribute before opening to all staff.
  [REVIEW] Rollback plan: Keep local break-glass admin access enabled until SSO is proven for at least one full business cycle.
```

The defective sample carries three deliberate defects — an expired
certificate placeholder, no NameID format, and a plain-HTTP endpoint —
and is correctly stopped:

```
========================================================================
Metadata: sample_metadata/idp-defective.xml
[PASS] XML well-formed: Metadata parses as XML
[PASS] entityID: https://idp.fabrikam-example.com/saml
[PASS] IDPSSODescriptor: Present
[FAIL] SSO endpoint: HTTP-Redirect -> http://idp.fabrikam-example.com/saml/sso is not HTTPS; credentials and assertions would cross the network in clear text
[FAIL] Signing certificate: Certificate is an EXPIRED PLACEHOLDER, not a real certificate -- replace it with the IdP's current signing certificate
[FAIL] NameIDFormat: None advertised -- the SP cannot agree a subject identifier format with the IdP
[WARN] Attributes advertised: No attributes listed in metadata -- confirm the release set (email, givenName, surname, groups) with the IdP out of band before go-live

--- Go-Live Readiness Report: idp-defective.xml ---
Verdict: NO-GO  (3 blocking, 1 warnings)
```

(The full demo prints the metadata checks and the deployment checklist
under each readiness report; the checklist is identical for both files
and is shown once above.)

## Design notes and limitations

- **Certificate expiry is really parsed**, using a minimal DER reader
  written for this project — no `cryptography`/`ssl` dependency. If a
  certificate's dates cannot be parsed, the tool says so (WARN) rather
  than guessing. The valid sample embeds a real self-signed certificate
  for a fictional IdP; the defective sample's certificate is an
  explicitly labelled expired placeholder, as is common in test
  metadata exchanged during implementations.
- **Validation is metadata-deep, not protocol-deep.** The tool does not
  fetch endpoints, perform a test authentication, or verify XML
  signatures on the metadata itself — those belong to integration
  testing with the actual IdP/SP pair.
- The checklist items are marked REVIEW, not PASS: they are facts about
  two organisations' configurations that no file inspection can prove,
  which is precisely why they belong on a go-live checklist.
- Both sample IdPs are fictional (`*.example.com`-style domains) and
  the sample data contains nothing from any real deployment.

## License

MIT — see `LICENSE`.
