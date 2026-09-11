package signature

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"go.podman.io/image/v5/internal/private"
	"go.podman.io/image/v5/internal/signature"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/signature/internal"
)

// isSignatureAcceptedBundle verifies a Cosign v3 sigstore bundle format signature.
func (pr *prSigstoreSigned) isSignatureAcceptedBundle(ctx context.Context, image private.UnparsedImage, sig signature.Sigstore, trustRoot *sigstoreSignedTrustRoot) (signatureAcceptanceResult, error) {
	bundleBytes := sig.UntrustedPayload()

	// Parse the bundle and validate its supported evidence format.
	bundle, err := internal.LoadBundle(bundleBytes)
	if err != nil {
		return sarRejected, err
	}

	// Handle DSSE bundles differently from MessageSignature bundles
	if bundle.IsDSSE() {
		return pr.verifyDSSEBundle(ctx, image, bundle, trustRoot)
	}

	// MessageSignature bundles contain only an artifact digest, not the signed
	// image identity required by this policy. A digest is not a signing payload.
	return sarRejected, internal.NewInvalidSignatureError("message signature bundle does not contain a signed image identity")
}

// verifyDSSEBundle verifies a bundle with DSSE envelope format.
// DSSE bundles contain attestations (not signatures over simple signing payloads).
func (pr *prSigstoreSigned) verifyDSSEBundle(ctx context.Context, image private.UnparsedImage, bundle *internal.Bundle, trustRoot *sigstoreSignedTrustRoot) (signatureAcceptanceResult, error) {
	keySources := 0
	if trustRoot.publicKeys != nil {
		keySources++
	}
	if trustRoot.fulcio != nil {
		keySources++
	}
	if trustRoot.pki != nil {
		keySources++
	}

	switch {
	case keySources > 1:
		return sarRejected, errors.New("Internal inconsistency: More than one of public key, Fulcio, or PKI specified")
	case keySources == 0:
		return sarRejected, errors.New("Internal inconsistency: A public key, Fulcio, or PKI must be specified.")

	case trustRoot.publicKeys != nil:
		// Verify against the policy's public keys and required log evidence.
		result, err := internal.VerifyBundle(bundle, internal.BundleVerifyOptions{
			PublicKeys:           trustRoot.publicKeys,
			RekorPublicKeys:      trustRoot.rekorPublicKeys,
			SkipTlogVerification: trustRoot.rekorPublicKeys == nil,
		})
		if err != nil {
			return sarRejected, err
		}
		// Use the verified payload for further validation
		return pr.validateDSSEPayload(ctx, image, result.EnvelopePayload, result.EnvelopePayloadType)

	case trustRoot.fulcio != nil:
		if trustRoot.rekorPublicKeys == nil {
			return sarRejected, errors.New("Internal inconsistency: Fulcio CA specified without a Rekor public key")
		}

		// Get certificate PEM from the bundle for Fulcio verification
		certPEM, err := bundle.GetCertificatePEM()
		if err != nil {
			return sarRejected, err
		}
		if certPEM == nil {
			return sarRejected, internal.NewInvalidSignatureError("bundle does not contain a certificate for Fulcio verification")
		}

		// Get intermediate chain PEM if present
		chainPEM, err := bundle.GetIntermediateChainPEM()
		if err != nil {
			return sarRejected, err
		}

		// For Fulcio verification, we need a trusted timestamp from Rekor
		if !bundle.HasTlogEntry() {
			return sarRejected, internal.NewInvalidSignatureError("bundle does not contain a transparency log entry required for Fulcio verification")
		}

		cert, err := bundle.GetCertificate()
		if err != nil || cert == nil {
			return sarRejected, internal.NewInvalidSignatureError("bundle has no usable Fulcio certificate")
		}
		integratedTime, err := internal.VerifyBundleTransparencyLog(bundle, cert.PublicKey, trustRoot.rekorPublicKeys)
		if err != nil {
			return sarRejected, err
		}
		if integratedTime.IsZero() {
			return sarRejected, internal.NewInvalidSignatureError("bundle transparency log entry has no integrated time")
		}

		// Verify the Fulcio certificate chain at the tlog integrated time
		pk, err := trustRoot.fulcio.verifyFulcioCertificateAtTime(integratedTime, certPEM, chainPEM)
		if err != nil {
			return sarRejected, err
		}

		// Now verify the DSSE envelope signature using the verified public key
		result, err := internal.VerifyBundle(bundle, internal.BundleVerifyOptions{
			PublicKeys:           []crypto.PublicKey{pk},
			SkipTlogVerification: true, // The log entry and its binding were verified above.
		})
		if err != nil {
			return sarRejected, err
		}

		return pr.validateDSSEPayload(ctx, image, result.EnvelopePayload, result.EnvelopePayloadType)

	case trustRoot.pki != nil:
		// Get certificate PEM from the bundle
		certPEM, err := bundle.GetCertificatePEM()
		if err != nil {
			return sarRejected, err
		}
		if certPEM == nil {
			return sarRejected, internal.NewInvalidSignatureError("bundle does not contain a certificate for PKI verification")
		}

		// Get intermediate chain PEM if present
		chainPEM, err := bundle.GetIntermediateChainPEM()
		if err != nil {
			return sarRejected, err
		}

		// Verify the PKI certificate chain
		pk, err := verifyPKI(trustRoot.pki, certPEM, chainPEM)
		if err != nil {
			return sarRejected, err
		}

		// Now verify the DSSE envelope signature using the verified public key
		result, err := internal.VerifyBundle(bundle, internal.BundleVerifyOptions{
			PublicKeys:           []crypto.PublicKey{pk},
			SkipTlogVerification: true,
		})
		if err != nil {
			return sarRejected, err
		}

		return pr.validateDSSEPayload(ctx, image, result.EnvelopePayload, result.EnvelopePayloadType)
	}

	return sarRejected, errors.New("Internal inconsistency: no key source matched")
}

// validateDSSEPayload validates the payload from a verified DSSE envelope.
// The payload is typically an in-toto attestation or a simple signing payload.
// The DSSE signature has already been verified, so we just need to validate the content.
func (pr *prSigstoreSigned) validateDSSEPayload(ctx context.Context, image private.UnparsedImage, payload []byte, payloadType string) (signatureAcceptanceResult, error) {
	switch payloadType {
	case signature.SigstoreSignatureMIMEType:
		parsedPayload, err := internal.ParseSigstorePayload(payload)
		if err != nil {
			return sarRejected, err
		}
		// Validate the parsed payload
		if err := pr.validateParsedPayload(ctx, image, parsedPayload); err != nil {
			return sarRejected, err
		}
		return sarAccepted, nil
	case signature.DSSEPayloadType:
		inTotoPayload, err := internal.ParseInTotoStatement(payload)
		if err != nil {
			return sarRejected, err
		}
		// Validate the in-toto statement
		if err := pr.validateInTotoStatement(ctx, image, inTotoPayload); err != nil {
			return sarRejected, err
		}
		return sarAccepted, nil
	}

	// If we can't parse the payload format, reject it
	return sarRejected, internal.NewInvalidSignatureError(fmt.Sprintf("unsupported DSSE payload type %q", payloadType))
}

// validateParsedPayload validates a parsed simple signing payload against the image.
func (pr *prSigstoreSigned) validateParsedPayload(ctx context.Context, image private.UnparsedImage, payload *internal.UntrustedSigstorePayload) error {
	// Validate the docker reference
	if !pr.SignedIdentity.matchesDockerReference(image, payload.UntrustedDockerReference()) {
		return PolicyRequirementError(fmt.Sprintf("Signature for identity %q is not accepted", payload.UntrustedDockerReference()))
	}

	// Validate the manifest digest
	m, _, err := image.Manifest(ctx)
	if err != nil {
		return err
	}
	digestMatches, err := manifest.MatchesDigest(m, payload.UntrustedDockerManifestDigest())
	if err != nil {
		return err
	}
	if !digestMatches {
		return PolicyRequirementError(fmt.Sprintf("Signature for digest %s does not match", payload.UntrustedDockerManifestDigest()))
	}

	return nil
}

// validateInTotoStatement validates an in-toto statement against the image.
func (pr *prSigstoreSigned) validateInTotoStatement(ctx context.Context, image private.UnparsedImage, statement *internal.InTotoStatement) error {
	// Get the manifest digest
	m, _, err := image.Manifest(ctx)
	if err != nil {
		return err
	}
	manifestDigest, err := manifest.Digest(m)
	if err != nil {
		return err
	}

	// Both claims must belong to the same signed subject. Cosign records the
	// image repository in subject.name; do not infer missing identity from image.
	for _, subject := range statement.Subject {
		if subject.Digest[manifestDigest.Algorithm().String()] == manifestDigest.Encoded() &&
			subject.Name != "" && pr.SignedIdentity.matchesDockerReference(image, subject.Name) {
			return nil
		}
	}
	return PolicyRequirementError(fmt.Sprintf("In-toto statement has no subject matching digest %s and the required signed identity", manifestDigest))
}
