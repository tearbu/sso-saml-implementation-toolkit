# SSO / SAML 2.0 Implementation Toolkit

Two tools I use on just about every SSO deployment: a **SAML 2.0 IdP metadata validator** and a **go-live
readiness report generator**.

## The problem it solves

SSO integrations tend to fail late. And badly. Usually for reasons that could have been caught much earlier, but only show up on the go-live call. The IdP signing certificate expired last month. The SSO endpoint is still the HTTP test URL. The metadata lists no NameID format. The ACS URL registered at the IdP differs from the SP's by a trailing slash. Or the two servers' clocks are six minutes apart, so every assertion comes back "not yet valid".

This toolkit catches the metadata problems automatically, before that call. It puts the rest into a structured GO / NO-GO readiness report.

## What the validator checks

- XML well-formedness and `EntityDescriptor` root
- `entityID` presence and format
- SSO endpoints: at least one present, binding recorded, **HTTPS
  enforced** (a plain-HTTP endpoint is a blocking failure)
- Signing certificate: presence in a signing `KeyDescriptor`, valid
  base64, and **expiry read from the certificate itself**. The validity
  dates come from a small standard-library ASN.1/DER parser
  (Certificate → TBSCertificate → validity). They are not guessed from filenames
- `NameIDFormat` values advertised
- Attributes advertised for release (email, givenName, surname, groups…)

The readiness report takes the validation result and adds the usual deployment checklist: clock skew, exact ACS URL matching, entityID agreement, attribute mapping, signature requirements, test users, and a rollback plan. Then it gives a verdict: **GO / GO with warnings / NO-GO**.

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

The valid sample passes everything. Look at the certificate dates. The DER parser read those from the embedded certificate:

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

The defective sample has three defects on purpose: an expired certificate placeholder, no NameID format, and a plain-HTTP endpoint. The tool stops it, as it should:

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

(The full demo prints the metadata checks and the deployment checklist under each readiness report. The checklist is the same for both files, so it is only shown once above.)

## Design notes and limitations

- **Certificate expiry is really parsed.** I wrote a minimal DER reader for this project, so there is no `cryptography`/`ssl` dependency. If the dates in a certificate cannot be parsed, the tool says so (WARN) instead of guessing. The valid sample embeds a real self-signed certificate for a fictional IdP. The defective sample's certificate is an expired placeholder, labelled as such. You see that a lot in test metadata during implementations.
- **Validation is metadata-deep, not protocol-deep.** The tool does not fetch endpoints, try a test authentication, or verify XML signatures on the metadata itself. That work belongs in integration testing with the actual IdP/SP pair.
- The checklist items are marked REVIEW, not PASS. They are facts about how two organisations have configured their sides, and no file inspection can prove them. That is exactly why they belong on a go-live checklist.
- Both sample IdPs are fictional (`*.example.com`-style domains). The sample data contains nothing from any real deployment.

## License

MIT. See `LICENSE`.
