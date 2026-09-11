package internal

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// rekorV1Record contains untrusted verification material from a persisted Rekor
// record. Decoding does not authenticate the record or its log evidence.
type rekorV1Record struct {
	signature   []byte
	key         crypto.PublicKey
	certificate *x509.Certificate // Non-nil when the record carries a certificate.
}

// decodeRekorV1Record extracts the first signature and its verification material.
// kind and version are the bundle's claims and must match the record body.
// This handles persisted entries, not Rekor submission requests.
// It validates persisted record structure; log authentication happens separately.
func decodeRekorV1Record(body []byte, kind, version string) (*rekorV1Record, error) {
	var recordKind, recordVersion string
	var spec json.RawMessage
	if err := ParanoidUnmarshalJSONObjectExactFields(body, map[string]any{
		"kind": &recordKind, "apiVersion": &recordVersion, "spec": &spec,
	}); err != nil {
		return nil, err
	}
	if recordKind != kind || recordVersion != version {
		return nil, fmt.Errorf("Rekor record kind/version does not match bundle")
	}
	if err := validateRekorV1Spec(spec, kind, version); err != nil {
		return nil, err
	}
	var signature, verifier []byte
	switch {
	case kind == "hashedrekord" && version == "0.0.1":
		var record RekorHashedrekordV001Schema
		if err := json.Unmarshal(spec, &record); err != nil {
			return nil, err
		}
		if record.Signature == nil || record.Signature.PublicKey == nil {
			return nil, fmt.Errorf("hashedrekord has no signature or public key")
		}
		signature, verifier = record.Signature.Content, record.Signature.PublicKey.Content
	case kind == "dsse" && version == "0.0.1":
		var record struct {
			Signatures []struct {
				Signature []byte `json:"signature"`
				Verifier  []byte `json:"verifier"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(spec, &record); err != nil {
			return nil, err
		}
		if len(record.Signatures) == 0 {
			return nil, fmt.Errorf("dsse record has no signatures")
		}
		signature, verifier = record.Signatures[0].Signature, record.Signatures[0].Verifier
	case kind == "intoto" && version == "0.0.2":
		var record struct {
			Content struct {
				Envelope struct {
					Signatures []struct {
						Sig       []byte `json:"sig"`
						PublicKey []byte `json:"publicKey"`
					} `json:"signatures"`
				} `json:"envelope"`
			} `json:"content"`
		}
		if err := json.Unmarshal(spec, &record); err != nil {
			return nil, err
		}
		if len(record.Content.Envelope.Signatures) == 0 {
			return nil, fmt.Errorf("intoto record has no signatures")
		}
		first := record.Content.Envelope.Signatures[0]
		// intoto v0.0.2 stores the base64 signature string inside a
		// base64-encoded byte field, unlike dsse v0.0.1.
		var err error
		signature, err = base64.StdEncoding.DecodeString(string(first.Sig))
		if err != nil {
			return nil, err
		}
		verifier = first.PublicKey
	default:
		return nil, fmt.Errorf("unsupported Rekor record %s/%s", kind, version)
	}
	return rekorV1Material(signature, verifier)
}

func rekorV1Material(signature, verifier []byte) (*rekorV1Record, error) {
	if len(signature) == 0 {
		return nil, fmt.Errorf("Rekor record has an empty signature")
	}
	block, rest := pem.Decode(verifier)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("Rekor verifier must contain one PEM object")
	}
	result := &rekorV1Record{signature: signature}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		result.certificate, result.key = cert, cert.PublicKey
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		result.key = key
	default:
		return nil, fmt.Errorf("unsupported Rekor verifier PEM type %q", block.Type)
	}
	return result, nil
}

// matches requires the same signature and signer representation as the bundle.
// For certificate-backed bundles, matching the public key alone is insufficient.
func (r *rekorV1Record) matches(signature []byte, key crypto.PublicKey, cert *x509.Certificate) bool {
	if !bytes.Equal(r.signature, signature) {
		return false
	}
	if cert != nil {
		return r.certificate != nil && cert.Equal(r.certificate)
	}
	if r.certificate != nil {
		return false
	}
	recordDER, err := x509.MarshalPKIXPublicKey(r.key)
	if err != nil {
		return false
	}
	keyDER, err := x509.MarshalPKIXPublicKey(key)
	return err == nil && bytes.Equal(recordDER, keyDER)
}
