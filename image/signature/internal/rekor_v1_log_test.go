package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	rekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
)

func TestVerifyRekorV1Proof(t *testing.T) {
	data, err := os.ReadFile("testdata/dsse.sigstore.json")
	require.NoError(t, err)
	b, err := LoadBundle(data)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	id := sha256.Sum256(der)
	entry := b.GetVerificationMaterial().TlogEntries[0]
	root := rfc6962.DefaultHasher.HashLeaf(entry.CanonicalizedBody)
	text := fmt.Sprintf("test.rekor - 123\n1\n%s\n", base64.StdEncoding.EncodeToString(root))
	hash := sha256.Sum256([]byte(text))
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	require.NoError(t, err)
	note := text + "\n— test.rekor " + base64.StdEncoding.EncodeToString(append(id[:4:4], signature...)) + "\n"
	entry.LogId.KeyId = id[:]
	entry.InclusionPromise = nil
	entry.InclusionProof = &rekor.InclusionProof{
		LogIndex: 0, TreeSize: 1, RootHash: root,
		Checkpoint: &rekor.Checkpoint{Envelope: note},
	}
	// The record's global index deliberately differs from the proof index.
	require.NoError(t, verifyRekorV1Proof(entry, &key.PublicKey))
	cert, err := b.GetCertificate()
	require.NoError(t, err)
	timestamp, err := VerifyBundleTransparencyLog(b, cert.PublicKey, []*ecdsa.PublicKey{&key.PublicKey})
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, timestamp)
	_, err = VerifyBundle(b, BundleVerifyOptions{PublicKeys: []crypto.PublicKey{cert.PublicKey}, RekorPublicKeys: []*ecdsa.PublicKey{&key.PublicKey}})
	require.NoError(t, err)
	for _, mutate := range []func(){
		func() { entry.InclusionProof.TreeSize++ },
		func() { entry.InclusionProof.LogIndex = -1 },
		func() { entry.InclusionProof.LogIndex = 1 },
		func() { entry.InclusionProof.RootHash = make([]byte, 32) },
		func() { entry.InclusionProof.Hashes = [][]byte{make([]byte, 32)} },
		func() { entry.InclusionProof.Checkpoint.Envelope = strings.Replace(note, "\n1\n", "\n2\n", 1) },
	} {
		entry.InclusionProof = &rekor.InclusionProof{LogIndex: 0, TreeSize: 1, RootHash: root, Checkpoint: &rekor.Checkpoint{Envelope: note}}
		mutate()
		require.Error(t, verifyRekorV1Proof(entry, &key.PublicKey))
	}
	for _, malformed := range []string{"", "\n\n", "x\n\n", text, note[:len(note)-1], text + "\n— log AA==\n"} {
		_, _, err := verifyRekorV1Checkpoint(malformed, &key.PublicKey)
		require.Error(t, err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, _, err = verifyRekorV1Checkpoint(note, &other.PublicKey)
	require.Error(t, err)
}

func FuzzDecodeRekorV1Record(f *testing.F) {
	f.Add([]byte(`{"kind":"dsse","apiVersion":"0.0.1","spec":{}}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, record := range [][2]string{{"dsse", "0.0.1"}, {"intoto", "0.0.2"}, {"hashedrekord", "0.0.1"}} {
			_, _ = decodeRekorV1Record(body, record[0], record[1])
		}
	})
}

func FuzzVerifyRekorV1Checkpoint(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)
	for _, seed := range []string{"", "\n\n", "rekor - 1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— rekor AA==\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, envelope string) {
		_, _, _ = verifyRekorV1Checkpoint(envelope, &key.PublicKey)
	})
}
