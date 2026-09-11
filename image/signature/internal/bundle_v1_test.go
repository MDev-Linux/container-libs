package internal

import (
	"os"
	"testing"

	bundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateBundleV1(t *testing.T) {
	data, err := os.ReadFile("testdata/dsse.sigstore.json")
	require.NoError(t, err)
	for _, mutate := range []func(*bundle.Bundle){
		func(b *bundle.Bundle) { b.MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.4" },
		func(b *bundle.Bundle) { b.MediaType = "invalid" },
		func(b *bundle.Bundle) { b.Content = nil },
		func(b *bundle.Bundle) { b.VerificationMaterial = nil },
		func(b *bundle.Bundle) { b.VerificationMaterial.Content = nil },
		func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionPromise = nil },
		func(b *bundle.Bundle) { b.MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.2" },
		func(b *bundle.Bundle) { b.MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.3" },
		func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries[0].KindVersion.Version = "0.0.9" },
		func(b *bundle.Bundle) {
			for len(b.VerificationMaterial.TlogEntries) < 33 {
				b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, b.VerificationMaterial.TlogEntries[0])
			}
		},
	} {
		b, err := LoadBundle(data)
		require.NoError(t, err)
		mutate(b.Bundle)
		require.Error(t, validateBundleV1(b.Bundle))
	}
}
