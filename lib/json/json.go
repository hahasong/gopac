package json

import (
	"bytes"
	"encoding/json"
)

// Marshal with SetEscapeHTML(false)
func Marshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	bytes := buffer.Bytes()
	if len(bytes) > 0 && bytes[len(bytes)-1] == '\n' {
		// trim right '\n'
		bytes = bytes[:len(bytes)-1]
	}
	return bytes, err
}

// MarshalIndent with SetEscapeHTML(false)
func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent(prefix, indent)
	err := encoder.Encode(v)
	bytes := buffer.Bytes()
	if len(bytes) > 0 && bytes[len(bytes)-1] == '\n' {
		// trim right '\n'
		bytes = bytes[:len(bytes)-1]
	}
	return bytes, err
}
