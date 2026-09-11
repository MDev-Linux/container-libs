# Bundle verification compatibility

This matrix describes the current image-policy integration, not every capability
of sigstore-go. It is a baseline for evaluating any future dependency replacement.

## Producer and format matrix

| Producer / format | Required behavior | Evidence and limitation |
| --- | --- | --- |
| Cosign v3.0.3 image signing, new bundle format | Reject payloads without a policy-matchable signed identity | Its signDigestBundle constructs an in-toto subject with digest and annotations but no name. This is a compatibility gap, not a supported end-to-end producer. |
| DSSE simple-signing payload with Docker reference | Accept only with valid signature, matching identity and digest, and required log evidence | Generated policy tests exercise the payload and identity checks. |
| DSSE in-toto statement with named image subject | Require identity and digest on the same subject | Generated image-policy tests, including Fulcio plus a signed Rekor DSSE entry. |
| Upstream dsse.sigstore.json | Verify DSSE and Rekor v1 intoto 0.0.2 SET evidence | Real upstream fixture, bundle v0.1; npm provenance, not an image-policy acceptance fixture. Producer binary version is not established. |
| Upstream sigstore.js@2.0.0-provenance.sigstore.json | Verify DSSE, SET and checkpoint/inclusion evidence | Upstream-named sigstore.js 2.0.0 fixture, bundle v0.1; not an image-policy acceptance fixture. |
| Bundle v0.2 | Preserve inclusion-proof requirements | Re-encoded upstream evidence exercises parsing and verification; not a native producer-version claim. |
| Bundle v0.3 | Preserve inclusion-proof and single-certificate requirements | Re-encoded upstream evidence exercises parsing and verification; not a native producer-version claim. |
| MessageSignature bundle | Reject under image policy | Digest-only content cannot supply the required signed image identity; retain rejection tests. |
| Legacy Cosign signature storage | Preserve existing behavior | Uses the existing non-bundle policy path, outside this refactor. |
| Rekor v2 | Reject | Outside the local Rekor v1 verifier's supported record formats. |
| RFC 3161-only timestamp evidence | Do not substitute for required Rekor evidence | The active policy paths do not verify RFC 3161 timestamps. Fulcio requires an authenticated Rekor integrated time. |

Cosign source:
https://github.com/sigstore/cosign/blob/v3.0.3/cmd/cosign/cli/sign/sign.go

Supporting ordinary Cosign v3.0.3 image-signing output requires resolving the
missing signed identity with maintainers. Do not infer identity from the registry,
relax SignedIdentity, or label generated named-subject tests as Cosign output.
Other Cosign versions and custom signing configurations require their own pinned
producer fixtures before claiming compatibility.

## Fixture provenance

The two JSON files are copied unchanged from sigstore-go v1.1.4:

- https://github.com/sigstore/sigstore-go/blob/v1.1.4/pkg/testing/data/bundles/dsse.sigstore.json
- https://github.com/sigstore/sigstore-go/blob/v1.1.4/pkg/testing/data/bundles/sigstore.js%402.0.0-provenance.sigstore.json

bundle-rekor.pub is the first transparency-log public key, PEM-encoded from:
https://github.com/sigstore/sigstore-go/blob/v1.1.4/pkg/testing/data/trusted-roots/public-good.json

Upstream is copyright The Sigstore Authors, licensed under Apache-2.0:
https://github.com/sigstore/sigstore-go/blob/v1.1.4/LICENSE

The fixtures contain public certificates and signatures, no private keys. Their
expired leaf certificates are intentional: log verification uses the authenticated
historical time. Tests use offline, pinned public-key material, never live trust
root downloads.

## Required checks before replacing the log verifier

Preserve signature/key binding, authenticated timestamps, checkpoint and Merkle
proof verification, certificate validity checks, duplicate-entry rejection,
entry limits, and required-log failure behavior. The DSSE fixture tests exercise
successful evidence verification and reject modified payloads, signatures, times,
SETs, bodies, log IDs, proof roots, missing entries, duplicate entries and wrong
log keys. Existing tests also cover an unrelated first envelope signature.

The generated Fulcio policy test verifies image acceptance and rejection of an
altered integrated time. It is a local cryptographic fixture, not evidence of
compatibility with a deployed Fulcio/Rekor service or a particular Cosign release.

The local verifier now replaces sigstore-go and retains checkpoint/inclusion
verification. Native producer fixtures are still required for broader image
workflow claims. The present coverage does not establish general Sigstore
compatibility; see ../REKOR-V1-IMPLEMENTATION.md for scope and stricter behavior.

## Validation

Both signature packages passed with Go 1.26 in Podman:

```text
go test -mod=vendor -tags containers_image_openpgp ./signature/internal ./signature
```

The workspace vendor tree was regenerated with `go work vendor` to match the
existing module requirements. Tests then passed against the regenerated vendor
tree with the repository mounted read-only in Podman.
