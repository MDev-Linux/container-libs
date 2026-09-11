package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	rekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// verifyRekorV1Log requires at least one authenticated, signer-bound entry.
// Only a SET can supply the returned time; inclusion proofs do not authenticate
// the entry's integratedTime. Unknown log keys and invalid SETs are skipped.
func verifyRekorV1Log(b *Bundle, signingKey crypto.PublicKey, keys []*ecdsa.PublicKey) (time.Time, error) {
	entries := b.GetVerificationMaterial().GetTlogEntries()
	if len(entries) > 32 {
		return time.Time{}, fmt.Errorf("too many tlog entries")
	}
	seen := map[string]bool{}
	records := make([]*rekorV1Record, len(entries))
	for i, entry := range entries {
		if entry == nil || entry.LogId == nil || len(entry.LogId.KeyId) == 0 || entry.KindVersion == nil || entry.LogIndex < 0 {
			return time.Time{}, fmt.Errorf("invalid Rekor entry")
		}
		id := fmt.Sprintf("%x/%d", entry.LogId.KeyId, entry.LogIndex)
		if seen[id] {
			return time.Time{}, fmt.Errorf("duplicate tlog entries")
		}
		seen[id] = true
		var err error
		records[i], err = decodeRekorV1Record(entry.CanonicalizedBody, entry.KindVersion.Kind, entry.KindVersion.Version)
		if err != nil {
			return time.Time{}, err
		}
	}
	trusted := map[string]*ecdsa.PublicKey{}
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return time.Time{}, err
		}
		id := sha256.Sum256(der)
		trusted[string(id[:])] = key
	}
	cert, err := b.GetCertificate()
	if err != nil {
		return time.Time{}, err
	}
	var signature []byte
	if b.IsDSSE() {
		envelope := b.GetDsseEnvelope()
		if len(envelope.Signatures) == 0 {
			return time.Time{}, fmt.Errorf("DSSE envelope has no signatures")
		}
		signature = envelope.Signatures[0].Sig
	} else {
		signature = b.GetMessageSignature().GetSignature()
	}
	verified := 0
	var authenticatedTime time.Time
	for i, entry := range entries {
		key := trusted[string(entry.LogId.KeyId)]
		if key == nil {
			continue
		}
		hasSET := len(entry.GetInclusionPromise().GetSignedEntryTimestamp()) != 0
		if !hasSET && entry.InclusionProof == nil {
			return time.Time{}, fmt.Errorf("entry has no inclusion evidence")
		}
		if hasSET {
			if entry.IntegratedTime < 0 {
				continue
			}
			payload, err := json.Marshal(UntrustedRekorPayload{
				Body: entry.CanonicalizedBody, IntegratedTime: entry.IntegratedTime,
				LogIndex: entry.LogIndex, LogID: hex.EncodeToString(entry.LogId.KeyId),
			})
			if err != nil {
				return time.Time{}, err
			}
			if _, err := verifyRekorSETSignature([]*ecdsa.PublicKey{key}, payload, entry.InclusionPromise.SignedEntryTimestamp); err != nil {
				continue
			}
		}
		if entry.InclusionProof != nil {
			if err := verifyRekorV1Proof(entry, key); err != nil {
				return time.Time{}, err
			}
		}
		if !records[i].matches(signature, signingKey, cert) {
			return time.Time{}, fmt.Errorf("transparency log signature or certificate does not match bundle")
		}
		if cert != nil && entry.IntegratedTime != 0 {
			t := time.Unix(entry.IntegratedTime, 0)
			if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
				return time.Time{}, fmt.Errorf("integrated time outside certificate validity")
			}
		}
		if hasSET && entry.IntegratedTime != 0 && authenticatedTime.IsZero() {
			authenticatedTime = time.Unix(entry.IntegratedTime, 0)
		}
		verified++
	}
	if verified == 0 {
		return time.Time{}, fmt.Errorf("not enough verified log entries")
	}
	return authenticatedTime, nil
}

// verifyRekorV1Proof authenticates the checkpoint and verifies inclusion of the
// exact record bytes. Both the root and tree size must match signed tree state.
func verifyRekorV1Proof(entry *rekor.TransparencyLogEntry, key *ecdsa.PublicKey) error {
	p := entry.InclusionProof
	// The entry index can be global across Rekor shards; the proof index
	// is local to the tree authenticated by this checkpoint.
	if p == nil || p.Checkpoint == nil || p.LogIndex < 0 || p.TreeSize <= 0 {
		return fmt.Errorf("invalid inclusion proof")
	}
	size, root, err := verifyRekorV1Checkpoint(p.Checkpoint.Envelope, key)
	if err != nil {
		return err
	}
	if size != uint64(p.TreeSize) || !bytes.Equal(root, p.RootHash) {
		return fmt.Errorf("inclusion proof does not match signed checkpoint")
	}
	leaf := rfc6962.DefaultHasher.HashLeaf(entry.CanonicalizedBody)
	return proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(p.LogIndex), uint64(p.TreeSize), leaf, p.Hashes, root)
}

// verifyRekorV1Checkpoint verifies Rekor v1's signed-note checkpoint format.
// The four-byte key hint is checked but never used as a substitute for a signature.
func verifyRekorV1Checkpoint(envelope string, key *ecdsa.PublicKey) (uint64, []byte, error) {
	split := strings.LastIndex(envelope, "\n\n")
	if split < 0 || split+2 >= len(envelope) || !strings.HasSuffix(envelope, "\n") {
		return 0, nil, fmt.Errorf("malformed checkpoint")
	}
	text, signatures := envelope[:split+1], envelope[split+2:len(envelope)-1]
	lines := strings.Split(text, "\n")
	if len(lines) < 4 || signatures == "" {
		return 0, nil, fmt.Errorf("incomplete checkpoint")
	}
	origin := strings.LastIndex(lines[0], " - ")
	if origin <= 0 {
		return 0, nil, fmt.Errorf("not a Rekor v1 checkpoint")
	}
	if _, err := strconv.ParseUint(lines[0][origin+3:], 10, 64); err != nil {
		return 0, nil, fmt.Errorf("invalid Rekor tree ID")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, nil, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != sha256.Size {
		return 0, nil, fmt.Errorf("invalid checkpoint root")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0, nil, err
	}
	id := sha256.Sum256(der)
	digest := sha256.Sum256([]byte(text))
	for _, line := range strings.Split(signatures, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "—" {
			return 0, nil, fmt.Errorf("invalid checkpoint signature line")
		}
		sig, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil || len(sig) <= 4 || binary.BigEndian.Uint32(sig[:4]) != binary.BigEndian.Uint32(id[:4]) {
			return 0, nil, fmt.Errorf("invalid checkpoint signature key hint")
		}
		if !ecdsa.VerifyASN1(key, digest[:], sig[4:]) {
			return 0, nil, fmt.Errorf("invalid checkpoint signature")
		}
	}
	return size, root, nil
}
