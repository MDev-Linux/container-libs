package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRekorV1Record(t *testing.T) {
	for _, name := range []string{"dsse.sigstore.json", "sigstore.js@2.0.0-provenance.sigstore.json"} {
		data, err := os.ReadFile("testdata/" + name)
		require.NoError(t, err)
		b, err := LoadBundle(data)
		require.NoError(t, err)
		entry := b.GetVerificationMaterial().TlogEntries[0]
		record, err := decodeRekorV1Record(entry.CanonicalizedBody, entry.KindVersion.Kind, entry.KindVersion.Version)
		require.NoError(t, err)
		assert.Equal(t, b.GetDsseEnvelope().Signatures[0].Sig, record.signature)
		cert, err := b.GetCertificate()
		require.NoError(t, err)
		assert.True(t, record.matches(b.GetDsseEnvelope().Signatures[0].Sig, cert.PublicKey, cert))
		assert.False(t, record.matches([]byte("different signature"), cert.PublicKey, cert))
		changedCert := *cert
		changedCert.Raw = append([]byte{}, cert.Raw...)
		changedCert.Raw[0] ^= 1
		assert.False(t, record.matches(record.signature, cert.PublicKey, &changedCert))
		_, err = decodeRekorV1Record(entry.CanonicalizedBody, "dsse", "0.0.1")
		require.Error(t, err)
		var outer map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(entry.CanonicalizedBody, &outer))
		for _, spec := range []string{
			`{"content":{"envelope":{"payloadType":"application/vnd.in-toto+json","signatures":[]}}}`,
			`{"content":null}`,
			`{"content":{},"content":{}}`,
			`{"content":{"envelope":{},"payloadHash":{"algorithm":"sha256","value":"00"}}}`,
		} {
			outer["spec"] = json.RawMessage(spec)
			encoded, err := json.Marshal(outer)
			require.NoError(t, err)
			_, err = decodeRekorV1Record(encoded, "intoto", "0.0.2")
			require.Error(t, err)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sig := []byte("signature bytes")
	for _, kind := range []string{"dsse", "hashedrekord"} {
		var spec any
		hash := map[string]any{"algorithm": "sha256", "value": strings.Repeat("0", 64)}
		if kind == "dsse" {
			spec = map[string]any{"envelopeHash": hash, "payloadHash": hash, "signatures": []any{map[string]any{"signature": sig, "verifier": keyPEM}}}
		} else {
			spec = map[string]any{"data": map[string]any{"hash": hash}, "signature": map[string]any{"content": sig, "publicKey": map[string]any{"content": keyPEM}}}
		}
		body, err := json.Marshal(map[string]any{"kind": kind, "apiVersion": "0.0.1", "spec": spec})
		require.NoError(t, err)
		record, err := decodeRekorV1Record(body, kind, "0.0.1")
		require.NoError(t, err)
		assert.True(t, record.matches(sig, &key.PublicKey, nil))
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		assert.False(t, record.matches(sig, &other.PublicKey, nil))
	}
	for _, body := range []string{
		`null`,
		`{"kind":"dsse","kind":"dsse","apiVersion":"0.0.1","spec":{}}`,
		`{"kind":"dsse","apiVersion":"0.0.2","spec":{}}`,
		`{"kind":"dsse","apiVersion":"0.0.1","spec":{"signatures":[]}}`,
		`{"kind":"dsse","apiVersion":"0.0.1","spec":{"signatures":[{"signature":"!","verifier":""}]}}`,
		`{"kind":"dsse","apiVersion":"0.0.1","spec":{"signatures":[{"signature":"YQ==","verifier":"` + base64.StdEncoding.EncodeToString([]byte("not PEM")) + `"}]}}`,
	} {
		_, err := decodeRekorV1Record([]byte(body), "dsse", "0.0.1")
		require.Error(t, err)
	}
}
