package utils

import (
	"encoding/base64"
	"strings"
)

func DecodeBase64URL(data string) ([]byte, error) {
	d := strings.ReplaceAll(strings.ReplaceAll(data, "-", "+"), "_", "/")
	return base64.StdEncoding.DecodeString(d)
}
