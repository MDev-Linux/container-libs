package internal

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// rekorObject accepts only the listed fields and rejects duplicates and nulls.
func rekorObject(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	fields := map[string]*json.RawMessage{}
	for _, name := range append(append([]string{}, required...), optional...) {
		fields[name] = new(json.RawMessage)
	}
	if err := ParanoidUnmarshalJSONObject(data, func(name string) any {
		if p, ok := fields[name]; ok {
			return p
		}
		return nil
	}); err != nil {
		return nil, err
	}
	result := map[string]json.RawMessage{}
	for name, value := range fields {
		if string(*value) == "null" {
			return nil, fmt.Errorf("null Rekor field %q", name)
		}
		if len(*value) != 0 {
			result[name] = *value
		}
	}
	for _, name := range required {
		if _, ok := result[name]; !ok {
			return nil, fmt.Errorf("missing Rekor field %q", name)
		}
	}
	return result, nil
}

func validateRekorHash(data []byte, sha256Only bool) error {
	fields, err := rekorObject(data, []string{"algorithm", "value"}, nil)
	if err != nil {
		return err
	}
	var algorithm, value string
	if err := json.Unmarshal(fields["algorithm"], &algorithm); err != nil {
		return err
	}
	if err := json.Unmarshal(fields["value"], &value); err != nil {
		return err
	}
	size := map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}[algorithm]
	if sha256Only && algorithm != "sha256" {
		return fmt.Errorf("Rekor envelope hashes require sha256")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || size == 0 || len(decoded) != size {
		return fmt.Errorf("invalid Rekor digest")
	}
	return nil
}

// validateRekorV1Spec validates persisted record structure before extraction.
// ProposedContent and other submission-only forms are deliberately not accepted.
func validateRekorV1Spec(spec []byte, kind, version string) error {
	switch {
	case kind == "hashedrekord" && version == "0.0.1":
		fields, err := rekorObject(spec, []string{"data", "signature"}, nil)
		if err != nil {
			return err
		}
		data, err := rekorObject(fields["data"], []string{"hash"}, nil)
		if err != nil {
			return err
		}
		if err := validateRekorHash(data["hash"], false); err != nil {
			return err
		}
		sig, err := rekorObject(fields["signature"], []string{"content", "publicKey"}, nil)
		if err != nil {
			return err
		}
		key, err := rekorObject(sig["publicKey"], []string{"content"}, nil)
		if err != nil {
			return err
		}
		return validateRekorSignature(sig["content"], key["content"], false)
	case kind == "dsse" && version == "0.0.1":
		fields, err := rekorObject(spec, []string{"envelopeHash", "payloadHash", "signatures"}, nil)
		if err != nil {
			return err
		}
		for _, name := range []string{"envelopeHash", "payloadHash"} {
			if err := validateRekorHash(fields[name], true); err != nil {
				return err
			}
		}
		return validateRekorSignatures(fields["signatures"], false)
	case kind == "intoto" && version == "0.0.2":
		fields, err := rekorObject(spec, []string{"content"}, nil)
		if err != nil {
			return err
		}
		content, err := rekorObject(fields["content"], []string{"envelope"}, []string{"hash", "payloadHash"})
		if err != nil {
			return err
		}
		for _, name := range []string{"hash", "payloadHash"} {
			if data, ok := content[name]; ok {
				if err := validateRekorHash(data, true); err != nil {
					return err
				}
			}
		}
		envelope, err := rekorObject(content["envelope"], []string{"payloadType", "signatures"}, []string{"payload"})
		if err != nil {
			return err
		}
		var payloadType string
		if err := json.Unmarshal(envelope["payloadType"], &payloadType); err != nil || payloadType == "" {
			return fmt.Errorf("invalid intoto payload type")
		}
		if payload, ok := envelope["payload"]; ok {
			var decoded []byte
			if err := json.Unmarshal(payload, &decoded); err != nil {
				return err
			}
		}
		return validateRekorSignatures(envelope["signatures"], true)
	default:
		return fmt.Errorf("unsupported Rekor record %s/%s", kind, version)
	}
}

func validateRekorSignatures(data []byte, intoto bool) error {
	var signatures []json.RawMessage
	if err := json.Unmarshal(data, &signatures); err != nil {
		return err
	}
	if len(signatures) == 0 {
		return fmt.Errorf("empty Rekor signature list")
	}
	sigName, keyName := "signature", "verifier"
	var optional []string
	if intoto {
		sigName, keyName, optional = "sig", "publicKey", []string{"keyid"}
	}
	for _, signature := range signatures {
		fields, err := rekorObject(signature, []string{sigName, keyName}, optional)
		if err != nil {
			return err
		}
		if value, ok := fields["keyid"]; ok {
			var keyID string
			if err := json.Unmarshal(value, &keyID); err != nil {
				return err
			}
		}
		if err := validateRekorSignature(fields[sigName], fields[keyName], intoto); err != nil {
			return err
		}
	}
	return nil
}

func validateRekorSignature(sigJSON, keyJSON []byte, intoto bool) error {
	var signature, key []byte
	if err := json.Unmarshal(sigJSON, &signature); err != nil {
		return err
	}
	if intoto {
		var err error
		signature, err = base64.StdEncoding.DecodeString(string(signature))
		if err != nil {
			return err
		}
	}
	if len(signature) == 0 {
		return fmt.Errorf("empty Rekor signature")
	}
	if err := json.Unmarshal(keyJSON, &key); err != nil {
		return err
	}
	_, err := rekorV1Material(signature, key)
	return err
}
