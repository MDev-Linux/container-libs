package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestVerifyBundleTransparencyLog(t *testing.T) {
	for _, filename := range []string{"dsse.sigstore.json", "sigstore.js@2.0.0-provenance.sigstore.json"} {
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + filename)
			require.NoError(t, err)
			keyPEM, err := os.ReadFile("testdata/bundle-rekor.pub")
			require.NoError(t, err)
			block, _ := pem.Decode(keyPEM)
			require.NotNil(t, block)
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			require.NoError(t, err)
			logKeys := []*ecdsa.PublicKey{key.(*ecdsa.PublicKey)}
			b, err := LoadBundle(data)
			require.NoError(t, err)
			cert, err := b.GetCertificate()
			require.NoError(t, err)
			require.NotNil(t, cert)
			timestamp, err := VerifyBundleTransparencyLog(b, cert.PublicKey, logKeys)
			require.NoError(t, err)
			assert.Equal(t, time.Unix(b.GetVerificationMaterial().TlogEntries[0].IntegratedTime, 0), timestamp)
			opts := BundleVerifyOptions{PublicKeys: []crypto.PublicKey{cert.PublicKey}, RekorPublicKeys: logKeys}
			_, err = VerifyBundle(b, opts)
			require.NoError(t, err)
			// An unverifiable entry must not prevent a separate valid entry from
			// satisfying the threshold, regardless of their order.
			for _, unknownKey := range []bool{false, true} {
				for _, prepend := range []bool{false, true} {
					mixed, err := LoadBundle(data)
					require.NoError(t, err)
					vm := mixed.GetVerificationMaterial()
					extra := proto.Clone(vm.TlogEntries[0]).(*rekor.TransparencyLogEntry)
					if unknownKey {
						extra.LogId.KeyId[0] ^= 1
					} else {
						extra.LogIndex++ // Distinct entry with an invalid SET.
					}
					if prepend {
						vm.TlogEntries = append([]*rekor.TransparencyLogEntry{extra}, vm.TlogEntries...)
					} else {
						vm.TlogEntries = append(vm.TlogEntries, extra)
					}
					got, err := VerifyBundleTransparencyLog(mixed, cert.PublicKey, logKeys)
					require.NoError(t, err)
					assert.Equal(t, timestamp, got)
				}
			}
			if b.GetVerificationMaterial().TlogEntries[0].GetInclusionProof() != nil {
				// Re-encode existing evidence to exercise version-specific parsing;
				// these variants are not claims about a producer's output version.
				for _, version := range []string{"0.2", "0.3"} {
					var raw map[string]any
					require.NoError(t, json.Unmarshal(data, &raw))
					raw["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=" + version
					if version == "0.3" {
						vm := raw["verificationMaterial"].(map[string]any)
						vm["certificate"] = vm["x509CertificateChain"].(map[string]any)["certificates"].([]any)[0]
						delete(vm, "x509CertificateChain")
					}
					encoded, err := json.Marshal(raw)
					require.NoError(t, err)
					variant, err := LoadBundle(encoded)
					require.NoError(t, err)
					_, err = VerifyBundle(variant, opts)
					require.NoError(t, err)
				}
			}
			for _, mutate := range []func(*Bundle){
				func(b *Bundle) { b.GetDsseEnvelope().Payload[0] ^= 1 },
				func(b *Bundle) { b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1 },
				func(b *Bundle) { b.GetVerificationMaterial().TlogEntries[0].IntegratedTime++ },
				func(b *Bundle) {
					b.GetVerificationMaterial().TlogEntries[0].GetInclusionPromise().SignedEntryTimestamp[0] ^= 1
				},
				func(b *Bundle) { b.GetVerificationMaterial().TlogEntries[0].CanonicalizedBody[0] ^= 1 },
				func(b *Bundle) { b.GetVerificationMaterial().TlogEntries[0].LogId.KeyId[0] ^= 1 },
				func(b *Bundle) { b.GetVerificationMaterial().TlogEntries = nil },
				func(b *Bundle) {
					b.GetVerificationMaterial().TlogEntries = append(b.GetVerificationMaterial().TlogEntries, b.GetVerificationMaterial().TlogEntries[0])
				},
			} {
				b, err := LoadBundle(data)
				require.NoError(t, err)
				mutate(b)
				_, err = VerifyBundle(b, opts)
				require.Error(t, err)
			}
			if proof := b.GetVerificationMaterial().TlogEntries[0].GetInclusionProof(); proof != nil {
				proof.RootHash[0] ^= 1
				_, err := VerifyBundle(b, opts)
				require.Error(t, err)
				proof.RootHash[0] ^= 1
			}
			wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			opts.RekorPublicKeys = []*ecdsa.PublicKey{&wrongKey.PublicKey}
			_, err = VerifyBundle(b, opts)
			require.Error(t, err)
		})
	}
	read := func(name string) []byte {
		data, err := os.ReadFile("testdata/" + name)
		require.NoError(t, err)
		return data
	}
	var set struct {
		SignedEntryTimestamp []byte
		Payload              struct {
			Body           []byte `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		}
	}
	require.NoError(t, json.Unmarshal(read("rekor-set"), &set))
	certBlock, _ := pem.Decode(read("rekor-cert"))
	require.NotNil(t, certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)
	logBlock, _ := pem.Decode(read("rekor.pub"))
	require.NotNil(t, logBlock)
	logKey, err := x509.ParsePKIXPublicKey(logBlock.Bytes)
	require.NoError(t, err)
	logKeys := []*ecdsa.PublicKey{logKey.(*ecdsa.PublicKey)}
	var raw map[string]any
	require.NoError(t, json.Unmarshal(createTestMessageSignatureBundle(t), &raw))
	logID, err := hex.DecodeString(set.Payload.LogID)
	require.NoError(t, err)
	raw["verificationMaterial"] = map[string]any{
		"x509CertificateChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": cert.Raw}}},
		"tlogEntries": []any{map[string]any{
			"logIndex":          set.Payload.LogIndex,
			"logId":             map[string]any{"keyId": logID},
			"kindVersion":       map[string]any{"kind": "hashedrekord", "version": "0.0.1"},
			"integratedTime":    set.Payload.IntegratedTime,
			"inclusionPromise":  map[string]any{"signedEntryTimestamp": set.SignedEntryTimestamp},
			"canonicalizedBody": set.Payload.Body,
		}},
	}
	raw["messageSignature"].(map[string]any)["signature"] = strings.TrimSpace(string(read("rekor-sig")))
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	b, err := LoadBundle(data)
	require.NoError(t, err)
	timestamp, err := VerifyBundleTransparencyLog(b, cert.PublicKey, logKeys)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(set.Payload.IntegratedTime, 0), timestamp)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = VerifyBundleTransparencyLog(b, cert.PublicKey, []*ecdsa.PublicKey{&wrongKey.PublicKey})
	require.Error(t, err)
	_, err = VerifyBundleTransparencyLog(b, &wrongKey.PublicKey, logKeys)
	require.ErrorContains(t, err, "certificate does not match")
	entry := b.Bundle.GetVerificationMaterial().GetTlogEntries()[0]
	entry.IntegratedTime++
	_, err = VerifyBundleTransparencyLog(b, cert.PublicKey, logKeys)
	require.Error(t, err)
	entry.IntegratedTime--
	entry.GetInclusionPromise().SignedEntryTimestamp[0] ^= 1
	_, err = VerifyBundleTransparencyLog(b, cert.PublicKey, logKeys)
	require.Error(t, err)
}

func TestDSSESignatureBindsEntirePayload(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	b, err := LoadBundle(createTestDSSEBundle(t))
	require.NoError(t, err)
	envelope := b.Bundle.GetDsseEnvelope()
	pae := ComputePAE(envelope.PayloadType, envelope.Payload)
	envelope.Signatures[0].Sig, err = ecdsa.SignASN1(rand.Reader, key, sha256Hash(pae))
	require.NoError(t, err)
	_, err = verifyDSSEWithPublicKeys(b, []crypto.PublicKey{&key.PublicKey})
	require.NoError(t, err)
	envelope.Payload[len(envelope.Payload)-1] ^= 1
	_, err = verifyDSSEWithPublicKeys(b, []crypto.PublicKey{&key.PublicKey})
	require.Error(t, err)

	// A signature over raw PAE authenticates only its first 32 bytes with
	// P-256. It must not be accepted as a signature over the DSSE message.
	envelope.Signatures[0].Sig, err = ecdsa.SignASN1(rand.Reader, key, pae)
	require.NoError(t, err)
	_, err = verifyDSSEWithPublicKeys(b, []crypto.PublicKey{&key.PublicKey})
	require.Error(t, err)

	// Log verification binds the first signature. A valid second signature
	// cannot rescue an unrelated first signature when requiring log evidence.
	second := &protodsse.Signature{}
	second.Sig, err = ecdsa.SignASN1(rand.Reader, key, sha256Hash(ComputePAE(envelope.PayloadType, envelope.Payload)))
	require.NoError(t, err)
	envelope.Signatures = append(envelope.Signatures, second)
	_, err = verifyDSSEWithPublicKeys(b, []crypto.PublicKey{&key.PublicKey})
	require.NoError(t, err)
	_, err = VerifyBundleTransparencyLog(b, &key.PublicKey, []*ecdsa.PublicKey{&key.PublicKey})
	require.ErrorContains(t, err, "ECDSA signature verification failed")
}

func TestBundleRequiresConfiguredTransparencyLog(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	b, err := LoadBundle(createTestDSSEBundle(t))
	require.NoError(t, err)
	e := b.Bundle.GetDsseEnvelope()
	e.Signatures[0].Sig, err = ecdsa.SignASN1(rand.Reader, key, sha256Hash(ComputePAE(e.PayloadType, e.Payload)))
	require.NoError(t, err)
	opts := BundleVerifyOptions{PublicKeys: []crypto.PublicKey{&key.PublicKey}, SkipTlogVerification: true}
	_, err = VerifyBundle(b, opts)
	require.NoError(t, err)
	opts.RekorPublicKeys = []*ecdsa.PublicKey{&key.PublicKey}
	_, err = VerifyBundle(b, opts)
	require.Error(t, err)
}

// TestLoadBundle tests bundle parsing from JSON bytes.
func TestLoadBundle(t *testing.T) {
	// Valid MessageSignature bundle
	t.Run("valid MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		require.NotNil(t, bundle)
		assert.True(t, bundle.IsMessageSignature())
		assert.False(t, bundle.IsDSSE())
	})

	// Valid DSSE bundle
	t.Run("valid DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		require.NotNil(t, bundle)
		assert.True(t, bundle.IsDSSE())
		assert.False(t, bundle.IsMessageSignature())
	})

	// Invalid JSON
	t.Run("invalid JSON", func(t *testing.T) {
		_, err := LoadBundle([]byte("not valid json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing sigstore bundle")
	})

	// Empty JSON object - sigstore-go validates media type
	t.Run("empty JSON object", func(t *testing.T) {
		_, err := LoadBundle([]byte("{}"))
		// sigstore-go validates the bundle and requires a valid media type
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing sigstore bundle")
	})
}

// TestBundleIsDSSE tests the IsDSSE helper.
func TestBundleIsDSSE(t *testing.T) {
	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.False(t, bundle.IsDSSE())
	})

	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.True(t, bundle.IsDSSE())
	})
}

// TestBundleIsMessageSignature tests the IsMessageSignature helper.
func TestBundleIsMessageSignature(t *testing.T) {
	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.True(t, bundle.IsMessageSignature())
	})

	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.False(t, bundle.IsMessageSignature())
	})
}

// TestBundleGetCertificatePEM tests certificate extraction.
func TestBundleGetCertificatePEM(t *testing.T) {
	t.Run("bundle with certificate", func(t *testing.T) {
		bundleJSON := createTestBundleWithCertificate(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		certPEM, err := bundle.GetCertificatePEM()
		require.NoError(t, err)
		require.NotNil(t, certPEM)

		// Verify it's valid PEM
		block, _ := pem.Decode(certPEM)
		require.NotNil(t, block)
		assert.Equal(t, "CERTIFICATE", block.Type)
	})

	t.Run("bundle without certificate", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		certPEM, err := bundle.GetCertificatePEM()
		require.NoError(t, err)
		assert.Nil(t, certPEM)
	})
}

// TestBundleGetIntermediateChainPEM tests intermediate chain extraction.
func TestBundleGetIntermediateChainPEM(t *testing.T) {
	t.Run("bundle with chain", func(t *testing.T) {
		bundleJSON := createTestBundleWithCertChain(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		chainPEM, err := bundle.GetIntermediateChainPEM()
		require.NoError(t, err)
		require.NotNil(t, chainPEM)

		// Verify it's valid PEM
		block, _ := pem.Decode(chainPEM)
		require.NotNil(t, block)
		assert.Equal(t, "CERTIFICATE", block.Type)
	})

	t.Run("bundle without chain", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		chainPEM, err := bundle.GetIntermediateChainPEM()
		require.NoError(t, err)
		assert.Nil(t, chainPEM)
	})
}

// TestBundleHasTlogEntry tests tlog entry detection.
func TestBundleHasTlogEntry(t *testing.T) {
	// Note: Creating valid tlog entries requires proper formatting that
	// sigstore-go validates strictly. We test the detection on bundles
	// that don't have tlog entries.
	t.Run("bundle without tlog entry", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.False(t, bundle.HasTlogEntry())
	})
}

// TestBundleString tests the String representation.
func TestBundleString(t *testing.T) {
	bundleJSON := createTestMessageSignatureBundle(t)
	bundle, err := LoadBundle(bundleJSON)
	require.NoError(t, err)

	str := bundle.String()
	assert.Contains(t, str, "Bundle{")
	assert.Contains(t, str, "isDSSE=")
}

// TestComputePAE tests Pre-Authentication Encoding computation.
func TestComputePAE(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"test": "data"}`)

	pae := ComputePAE(payloadType, payload)

	// Verify PAE format: "DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>"
	// "application/vnd.in-toto+json" is 28 characters
	expected := "DSSEv1 28 application/vnd.in-toto+json 16 {\"test\": \"data\"}"
	assert.Equal(t, expected, string(pae))
}

// Helper functions to create test bundles

// createTestMessageSignatureBundle creates a minimal valid MessageSignature bundle.
func createTestMessageSignatureBundle(t *testing.T) []byte {
	t.Helper()

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)

	// Create a test signature (not cryptographically valid, just for parsing tests)
	testSig := []byte("test-signature-bytes")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"hint": "test-key-hint",
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestDSSEBundle creates a minimal valid DSSE bundle.
func createTestDSSEBundle(t *testing.T) []byte {
	t.Helper()

	// Create a simple signing payload
	payload := map[string]any{
		"critical": map[string]any{
			"type": "cosign container image signature",
			"image": map[string]string{
				"docker-manifest-digest": "sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
			},
			"identity": map[string]string{
				"docker-reference": "example.com/test:latest",
			},
		},
		"optional": nil,
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	// Create a test signature
	testSig := []byte("test-dsse-signature")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"hint": "test-key-hint",
			},
		},
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(payloadBytes),
			"payloadType": "application/vnd.dev.cosign.simplesigning.v1+json",
			"signatures": []map[string]any{
				{
					"sig":   base64.StdEncoding.EncodeToString(testSig),
					"keyid": "test-key-id",
				},
			},
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestBundleWithCertificate creates a bundle with a certificate.
func createTestBundleWithCertificate(t *testing.T) []byte {
	t.Helper()

	// Generate a test certificate
	certDER := generateTestCertificate(t)

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)
	testSig := []byte("test-signature-bytes")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"x509CertificateChain": map[string]any{
				"certificates": []map[string]any{
					{
						"rawBytes": base64.StdEncoding.EncodeToString(certDER),
					},
				},
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestBundleWithCertChain creates a bundle with a certificate chain.
func createTestBundleWithCertChain(t *testing.T) []byte {
	t.Helper()

	// Generate test certificates
	certDER := generateTestCertificate(t)
	intermediateDER := generateTestCertificate(t) // Use same for simplicity

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)
	testSig := []byte("test-signature-bytes")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"x509CertificateChain": map[string]any{
				"certificates": []map[string]any{
					{
						"rawBytes": base64.StdEncoding.EncodeToString(certDER),
					},
					{
						"rawBytes": base64.StdEncoding.EncodeToString(intermediateDER),
					},
				},
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestBundleWithTlog creates a bundle with a transparency log entry.
func createTestBundleWithTlog(t *testing.T) []byte {
	t.Helper()

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)
	testSig := []byte("test-signature-bytes")

	integratedTime := time.Now().Unix()

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"hint": "test-key-hint",
			},
			"tlogEntries": []map[string]any{
				{
					"logIndex":       "12345",
					"logId":          map[string]any{"keyId": base64.StdEncoding.EncodeToString([]byte("test-log-id"))},
					"integratedTime": integratedTime,
					"inclusionPromise": map[string]any{
						"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("test-set")),
					},
					"canonicalizedBody": base64.StdEncoding.EncodeToString([]byte("test-body")),
				},
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// generateTestCertificate generates a self-signed test certificate.
func generateTestCertificate(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return certDER
}
