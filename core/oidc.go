package core

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/seatedro/guam-oauth/utils"
)

type OIDCPayload struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
}

func DecodeToken(idToken string) (*OIDCPayload, error) {
	idTokenParts := strings.Split(idToken, ".")
	if len(idTokenParts) != 3 {
		return nil, errors.New("invalid id token")
	}

	base64Payload := idTokenParts[1]
	payload, err := utils.DecodeBase64URL(base64Payload)
	if err != nil {
		return nil, err
	}

	var oidcPayload OIDCPayload
	err = json.Unmarshal(payload, &oidcPayload)
	if err != nil {
		return nil, err
	}

	return &oidcPayload, nil
}
