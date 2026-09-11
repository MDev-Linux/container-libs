package internal

import (
	"fmt"
	"strings"

	bundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

// validateBundleV1 enforces the supported bundle versions and their log evidence
// requirements. Rekor v2 record types are intentionally rejected.
func validateBundleV1(b *bundle.Bundle) error {
	version := strings.TrimPrefix(b.MediaType, "application/vnd.dev.sigstore.bundle+json;version=")
	if version == b.MediaType {
		version = strings.TrimSuffix(strings.TrimPrefix(b.MediaType, "application/vnd.dev.sigstore.bundle.v"), "+json")
		if b.MediaType != "application/vnd.dev.sigstore.bundle.v"+version+"+json" {
			return fmt.Errorf("invalid bundle media type")
		}
	}
	if version != "0.1" && version != "0.2" && version != "0.3" {
		return fmt.Errorf("unsupported bundle version")
	}
	if b.Content == nil || b.VerificationMaterial == nil || b.VerificationMaterial.Content == nil {
		return fmt.Errorf("missing bundle content or verification material")
	}
	vm := b.VerificationMaterial
	if version == "0.3" && vm.GetX509CertificateChain() != nil {
		return fmt.Errorf("bundle v0.3 requires a single certificate")
	}
	if len(vm.TlogEntries) > 32 {
		return fmt.Errorf("too many tlog entries")
	}
	for _, entry := range vm.TlogEntries {
		if entry == nil || entry.KindVersion == nil || entry.LogId == nil || len(entry.LogId.KeyId) == 0 || entry.LogIndex < 0 {
			return fmt.Errorf("invalid transparency log entry")
		}
		if _, err := decodeRekorV1Record(entry.CanonicalizedBody, entry.KindVersion.Kind, entry.KindVersion.Version); err != nil {
			return err
		}
		if version == "0.1" && len(entry.GetInclusionPromise().GetSignedEntryTimestamp()) == 0 {
			return fmt.Errorf("bundle v0.1 requires an inclusion promise")
		}
		if version != "0.1" && entry.InclusionProof == nil {
			return fmt.Errorf("bundle v0.2 and v0.3 require an inclusion proof")
		}
		if entry.InclusionProof != nil && entry.InclusionProof.GetCheckpoint().GetEnvelope() == "" {
			return fmt.Errorf("missing checkpoint")
		}
	}
	return nil
}
