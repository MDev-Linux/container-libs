# Rekor v1 implementation

This branch starts from fix-388-sigstore-bundle-support-testing.

The active bundle verification path now uses local Rekor v1 verification:

- Strict persisted-record decoding for hashedrekord 0.0.1, dsse 0.0.1, and
  intoto 0.0.2, including nested fields, hash encodings, and verifier material.
- Shared SET canonicalization/authentication, also used by the legacy verifier.
- Signature and certificate binding, required-log behavior, unknown-key handling,
  duplicate rejection, entry limits, and certificate validity checks.
- Rekor v1 signed checkpoints and inclusion proofs using transparency-dev/merkle.
- Protobuf JSON bundle parsing with supported version and evidence validation.

No image-identity policy changes are included. Rekor v2 is explicitly unsupported.
The Cosign v3.0.3 missing-signed-identity issue remains unresolved.

## Validation and deliberate restrictions

Both signature packages pass in Podman with Go 1.26 and vendor mode. Tests cover
the existing real DSSE fixtures, generated Fulcio policy acceptance, signature and
log tampering, certificate binding, format variants, proof-only verification
returning no authenticated time, and malformed checkpoint/proof cases.

The initial extraction tests agreed with the upstream decoder for the two real
in-toto fixtures. That test-only upstream import was removed before vendoring.
This is not a claim of exhaustive differential or producer conformance testing.

The shared TestVerifyBundleTransparencyLog corpus also passes against both this
implementation and an isolated snapshot of the upstream-backed implementation
at 8b4110ddda. This includes the two real fixtures, evidence tampering, format
variants, and a valid entry mixed with an unknown-key or invalid-SET entry in
both orders. It is a bounded behavioral comparison, not exhaustive equivalence.

Additional local validation with Go 1.26 in Podman:

- All signature subpackages pass with the race detector and containers_image_openpgp.
- go vet passes across the signature subpackages.
- A ten-second checkpoint fuzz run passed 136,625 inputs; the earlier record
  decoder fuzz run passed 42,315 inputs. Neither duration establishes fuzz completeness.
- The broader image-module run was not clean: storage tests do not build with
  containers_image_storage_stub, root execution defeats permission assertions,
  and a credential-helper test attempts to chmod a read-only source fixture.
  The normal non-root Linux CI environment and configured golangci-lint checks
  still need to run; these results do not substitute for CI.

The decoder rejects unknown/duplicate fields and invalid digest lengths.
The checkpoint verifier additionally requires the proof tree size to equal the
signed tree size and compares root hashes byte-for-byte. The global Rekor entry
index is not required to equal the shard-local proof index: a real fixture has
different values. Inclusion uses the proof's local index and authenticated tree.

Only the explicit 0.1, 0.2, and 0.3 bundle media-type forms are supported.
Certificate parsing errors are propagated rather than treated as absent material.
These stricter behaviors should be reviewed as part of adopting the replacement.
Digest checks here validate encoding and length, not the record's payload hash
against the artifact. Binding is through the verified signature and signer,
as in the previous verifier.

## Cosign v3.0.3 signed identity

The pinned [signing implementation](https://github.com/sigstore/cosign/blob/v3.0.3/cmd/cosign/cli/sign/sign.go)
constructs the new-bundle subject with digest and annotations but no name.
Although the [command options](https://github.com/sigstore/cosign/blob/v3.0.3/cmd/cosign/cli/options/sign.go)
expose --sign-container-identity and --payload, the former is consumed by the
legacy signDigest path and the latter's bytes are not passed to signDigestBundle.
Annotations do not populate subject.name. These options therefore do not repair
the new-bundle signed-identity gap under the current policy.

Do not infer identity from the registry location or silently relax policy to
digest-only acceptance. A producer change or an agreed alternative signed-identity
contract is needed before claiming native new-bundle image-signing compatibility.
Legacy-format signing remains a different workflow, not evidence of compatibility
with the new bundle path. No signatures were uploaded to a public log in this
investigation.

## Dependency reduction

Regenerated with the repository's make vendor target, including module tidy,
verification, vendoring and workspace synchronization. sigstore-go, Rekor,
OpenAPI, TUF and timestamp-authority packages are absent from vendor/modules.txt.
The protobuf definitions and small Merkle library remain.
Workspace synchronization also aligns image module requirements with versions
already selected by common; vendor metadata is regenerated after that sync.

On this checkout, vendor disk usage fell from 62,724 KiB to 55,400 KiB (about
11.7%). The tracked vendor diff removes roughly 167,000 lines. Disk usage is not
a measurement of linked binary size.

## Remaining review

Before declaring broad producer compatibility, resolve the signed-identity
contract and add native fixtures for the chosen image-signing workflow. Review
the stricter parsing/checkpoint behavior and expand fuzz/conformance coverage.
Do not describe this v1 implementation as supporting arbitrary Sigstore bundles.
