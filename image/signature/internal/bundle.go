package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Bundle is a parsed Sigstore bundle with validated Rekor v1 evidence structure.
type Bundle struct {
	*protobundle.Bundle
}

// LoadBundle parses a sigstore bundle from JSON bytes.
// This is the primary entry point for bundle parsing.
func LoadBundle(bundleBytes []byte) (*Bundle, error) {
	b := new(protobundle.Bundle)
	if err := protojson.Unmarshal(bundleBytes, b); err != nil {
		return nil, NewInvalidSignatureError(fmt.Sprintf("parsing sigstore bundle: %v", err))
	}
	if err := validateBundleV1(b); err != nil {
		return nil, NewInvalidSignatureError(fmt.Sprintf("parsing sigstore bundle: %v", err))
	}
	return &Bundle{Bundle: b}, nil
}

// IsDSSE returns true if the bundle contains a DSSE envelope (attestation).
func (b *Bundle) IsDSSE() bool {
	return b.Bundle.GetDsseEnvelope() != nil
}

// IsMessageSignature returns true if the bundle contains a message signature.
func (b *Bundle) IsMessageSignature() bool {
	return b.Bundle.GetMessageSignature() != nil
}

// GetCertificate extracts the signing certificate from the bundle.
// Returns nil if no certificate is present (e.g., public key signed).
func (b *Bundle) GetCertificate() (*x509.Certificate, error) {
	vm := b.GetVerificationMaterial()
	var raw []byte
	if cert := vm.GetCertificate(); cert != nil {
		raw = cert.RawBytes
	} else if chain := vm.GetX509CertificateChain(); chain != nil && len(chain.Certificates) != 0 {
		raw = chain.Certificates[0].GetRawBytes()
	} else if vm.GetPublicKey() != nil {
		return nil, nil
	}
	if len(raw) == 0 {
		return nil, NewInvalidSignatureError("missing certificate")
	}
	return x509.ParseCertificate(raw)
}

// GetCertificatePEM returns the signing certificate as PEM-encoded bytes.
// Returns nil if no certificate is present.
func (b *Bundle) GetCertificatePEM() ([]byte, error) {
	vm := b.Bundle.GetVerificationMaterial()
	if vm == nil {
		return nil, nil
	}

	// Try X509CertificateChain first (preferred format)
	if chain := vm.GetX509CertificateChain(); chain != nil {
		certs := chain.GetCertificates()
		if len(certs) > 0 {
			return pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certs[0].GetRawBytes(),
			}), nil
		}
	}

	// Fall back to single Certificate
	if cert := vm.GetCertificate(); cert != nil {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.GetRawBytes(),
		}), nil
	}

	return nil, nil
}

// GetIntermediateChainPEM returns the intermediate certificate chain as PEM-encoded bytes.
// Returns nil if no intermediate chain is present.
func (b *Bundle) GetIntermediateChainPEM() ([]byte, error) {
	vm := b.Bundle.GetVerificationMaterial()
	if vm == nil {
		return nil, nil
	}

	// Only X509CertificateChain has intermediates
	chain := vm.GetX509CertificateChain()
	if chain == nil {
		return nil, nil
	}
	certs := chain.GetCertificates()
	if len(certs) <= 1 {
		return nil, nil // No intermediates
	}

	// All certs after the first are intermediates
	var chainPEM []byte
	for _, cert := range certs[1:] {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.GetRawBytes(),
		})...)
	}
	return chainPEM, nil
}

// HasTlogEntry returns true if the bundle contains transparency log entries.
func (b *Bundle) HasTlogEntry() bool {
	vm := b.Bundle.GetVerificationMaterial()
	return vm != nil && len(vm.GetTlogEntries()) > 0
}

// BundleVerificationResult contains the results of verifying a sigstore bundle.
type BundleVerificationResult struct {
	// PublicKey is the public key that verified the signature
	PublicKey crypto.PublicKey
	// EnvelopePayload is the raw DSSE envelope payload for attestations
	EnvelopePayload []byte
	// EnvelopePayloadType is the DSSE payload type
	EnvelopePayloadType string
}

// BundleVerifyOptions contains options for bundle verification.
type BundleVerifyOptions struct {
	// PublicKeys are trusted public keys for non-Fulcio verification
	PublicKeys []crypto.PublicKey
	// RekorPublicKeys are the Rekor transparency log public keys
	RekorPublicKeys []*ecdsa.PublicKey
	// SkipTlogVerification skips transparency log verification
	SkipTlogVerification bool
}

// VerifyBundle verifies a parsed DSSE bundle with policy-selected keys.
// If Rekor keys are supplied, log evidence is required even when
// SkipTlogVerification is true.
func VerifyBundle(b *Bundle, opts BundleVerifyOptions) (*BundleVerificationResult, error) {
	result, err := verifyDSSEWithPublicKeys(b, opts.PublicKeys)
	if err != nil {
		return nil, err
	}
	if !opts.SkipTlogVerification || opts.RekorPublicKeys != nil {
		if _, err := VerifyBundleTransparencyLog(b, result.PublicKey, opts.RekorPublicKeys); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// VerifyBundleTransparencyLog authenticates log evidence and binds it to the
// bundle signature and signing key. The returned time is authenticated by a SET;
// inclusion proofs alone do not authenticate the integrated time.
func VerifyBundleTransparencyLog(b *Bundle, signingKey crypto.PublicKey, rekorKeys []*ecdsa.PublicKey) (time.Time, error) {
	// The log verifier binds the entry to the first envelope signature. Verify
	// that exact signature, rather than allowing an unrelated logged signature
	// alongside a different, valid signature over this payload.
	if b.IsDSSE() {
		envelope := b.Bundle.GetDsseEnvelope()
		if len(envelope.Signatures) == 0 {
			return time.Time{}, NewInvalidSignatureError("DSSE envelope has no signatures")
		}
		if err := verifySignature(signingKey, sha256Hash(ComputePAE(envelope.PayloadType, envelope.Payload)), envelope.Signatures[0].Sig); err != nil {
			return time.Time{}, err
		}
	}
	if cert, err := b.GetCertificate(); err != nil {
		return time.Time{}, err
	} else if cert != nil {
		certKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return time.Time{}, err
		}
		selectedKey, err := x509.MarshalPKIXPublicKey(signingKey)
		if err != nil {
			return time.Time{}, err
		}
		if string(certKey) != string(selectedKey) {
			return time.Time{}, NewInvalidSignatureError("bundle certificate does not match verified signing key")
		}
	}
	timestamp, err := verifyRekorV1Log(b, signingKey, rekorKeys)
	if err != nil {
		return time.Time{}, NewInvalidSignatureError(fmt.Sprintf("verifying bundle transparency log: %v", err))
	}
	return timestamp, nil
}

// verifyDSSEWithPublicKeys verifies a DSSE envelope using provided public keys.
func verifyDSSEWithPublicKeys(b *Bundle, publicKeys []crypto.PublicKey) (*BundleVerificationResult, error) {
	envelope := b.Bundle.GetDsseEnvelope()
	if envelope == nil {
		return nil, NewInvalidSignatureError("bundle does not contain a DSSE envelope")
	}

	if len(envelope.Signatures) == 0 {
		return nil, NewInvalidSignatureError("DSSE envelope has no signatures")
	}

	// In protobuf, Payload is already []byte
	payload := envelope.Payload

	// Compute PAE
	paeBytes := ComputePAE(envelope.PayloadType, payload)

	// Try each public key
	for _, pk := range publicKeys {
		for _, sig := range envelope.Signatures {
			// In protobuf, Sig is already []byte
			sigBytes := sig.Sig

			if err := verifySignature(pk, sha256Hash(paeBytes), sigBytes); err == nil {
				return &BundleVerificationResult{
					PublicKey:           pk,
					EnvelopePayload:     payload,
					EnvelopePayloadType: envelope.PayloadType,
				}, nil
			}
		}
	}

	return nil, NewInvalidSignatureError("DSSE signature verification failed with all provided keys")
}

// verifySignature verifies a raw signature over data using a public key.
func verifySignature(publicKey crypto.PublicKey, data, signature []byte) error {
	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(pk, data, signature)
	default:
		return NewInvalidSignatureError(fmt.Sprintf("unsupported key type: %T", publicKey))
	}
}

// verifyECDSA verifies an ECDSA signature.
func verifyECDSA(publicKey *ecdsa.PublicKey, data, signature []byte) error {
	// The caller supplies the digest, never unhashed message bytes. ECDSA
	// truncates oversized digests, which would leave message suffixes unsigned.
	if ecdsa.VerifyASN1(publicKey, data, signature) {
		return nil
	}

	return NewInvalidSignatureError("ECDSA signature verification failed")
}

// sha256Hash computes SHA256 hash.
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// ComputePAE computes the Pre-Authentication Encoding for DSSE verification.
func ComputePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType,
		len(payload), string(payload)))
}

// String returns a debug representation of the bundle.
func (b *Bundle) String() string {
	hasCert := false
	if cert, _ := b.GetCertificate(); cert != nil {
		hasCert = true
	}
	return fmt.Sprintf("Bundle{isDSSE=%v, hasCert=%v, hasTlog=%v}",
		b.IsDSSE(), hasCert, b.HasTlogEntry())
}
