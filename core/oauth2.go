package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rohitp934/guam-oauth/utils"

	guamutils "github.com/rohitp934/guam/utils"
)

type GetAuthorizationUrlResponse struct {
	State *string
	URL   url.URL
}

type Oauth2ProviderAuth[T any] interface {
	ValidateCallback(code string) (T, error)
	GetAuthorizationURL() (GetAuthorizationUrlResponse, error)
}

type GetAuthorizationUrlWithPKCEResponse struct {
	State        *string
	CodeVerifier string
	URL          url.URL
}

type Oauth2ProviderAuthWithPKCE interface {
	ValidateCallback(code, codeVerifier string) (ProviderUserAuth, error)
	GetrAuthizationURL() (GetAuthorizationUrlWithPKCEResponse, error)
}

type CreateOauth2AuthorizationURLOptions struct {
	URL     string
	Options struct {
		RedirectUri *string
		ClientId    string
		Scope       []string
	}
}

func CreateOauth2AuthorizationURL(
	opts CreateOauth2AuthorizationURLOptions,
) (*GetAuthorizationUrlResponse, error) {
	state := GenerateState()
	responseType := "code"
	scope := strings.Join(opts.Options.Scope, " ")
	authorizationURL, err := utils.CreateURL(
		opts.URL,
		map[string]*string{
			"response_type": &responseType,
			"client_id":     &opts.Options.ClientId,
			"scope":         &scope,
			"state":         &state,
			"redirect_uri":  opts.Options.RedirectUri,
		},
	)
	if err != nil {
		return nil, err
	}

	return &GetAuthorizationUrlResponse{
		State: &state,
		URL:   *authorizationURL,
	}, nil
}

type CreateOauth2WithPKCEAuthorizationURLOptions struct {
	URL     string
	Options struct {
		RedirectUri   *string
		ClientId      string
		CodeChallenge string
		Scope         []string
	}
}

func CreateOauth2AuthorizationURLWithPKCE(
	opts CreateOauth2AuthorizationURLOptions,
) (*GetAuthorizationUrlWithPKCEResponse, error) {
	state := GenerateState()
	codeVerifier := guamutils.GenerateRandomString(
		96,
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_.~",
	)
	responseType := "code"
	scope := strings.Join(opts.Options.Scope, " ")
	codeChallengeMethod := "S256"
	codeChallenge, err := GenereatePKCECodeChallenge(codeChallengeMethod, codeVerifier)
	if err != nil {
		return nil, err
	}
	authorizationURL, err := utils.CreateURL(
		opts.URL,
		map[string]*string{
			"response_type":         &responseType,
			"client_id":             &opts.Options.ClientId,
			"scope":                 &scope,
			"state":                 &state,
			"redirect_uri":          opts.Options.RedirectUri,
			"code_challenge_method": &codeChallengeMethod,
			"code_challenge":        &codeChallenge,
		},
	)
	if err != nil {
		return nil, err
	}

	return &GetAuthorizationUrlWithPKCEResponse{
		State:        &state,
		URL:          *authorizationURL,
		CodeVerifier: codeVerifier,
	}, nil
}

type Oauth2AuthenticateWith int

const (
	AUTHENTICATE_WITH_BASIC Oauth2AuthenticateWith = iota
	AUTHENTICATE_WITH_CLIENT_SECRET
)

type Oauth2ClientPassword struct {
	ClientSecret     string
	AuthenticateWith string
}
type Oauth2ValidationOptions struct {
	RedirectUri    *string
	CodeVerifier   *string
	ClientPassword *Oauth2ClientPassword
	ClientId       string
}
type ValidateOauth2AuthorizationCodeOptions struct {
	AuthorizationCode string
	URL               string
	Options           Oauth2ValidationOptions
}

func ValidateOauth2AuthorizationCode(
	opts ValidateOauth2AuthorizationCodeOptions,
) (*[]byte, error) {
	body := map[string]string{
		"code":       opts.AuthorizationCode,
		"client_id":  opts.Options.ClientId,
		"grant_type": "authorization_code",
	}

	if opts.Options.RedirectUri != nil {
		body["redirect_uri"] = *opts.Options.RedirectUri
	}

	if opts.Options.CodeVerifier != nil {
		body["code_verifier"] = *opts.Options.CodeVerifier
	}

	if opts.Options.ClientPassword != nil &&
		opts.Options.ClientPassword.AuthenticateWith == "client_secret" {
		body["client_secret"] = opts.Options.ClientPassword.ClientSecret
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/x-www-form-urlencoded")

	if opts.Options.ClientPassword != nil &&
		opts.Options.ClientPassword.AuthenticateWith == "http_basic_auth" {
		encodedString := base64.StdEncoding.EncodeToString(
			[]byte(
				fmt.Sprintf(
					"%s:%s",
					opts.Options.ClientId,
					opts.Options.ClientPassword.ClientSecret,
				),
			),
		)
		authn, err := utils.AuthorizationHeader(
			utils.AUTHORIZATION_HEADER_TYPE_BASIC,
			encodedString,
		)
		if err != nil {
			return nil, err
		}
		headers.Add("Authorization", authn)
	}

	bodyBytes, err := json.Marshal(&body)
	if err != nil {
		return nil, err
	}

	reader := io.NopCloser(bytes.NewReader(bodyBytes))

	req := http.Request{
		Method: http.MethodPost,
		Header: headers,
		Body:   reader,
	}
	response, err := utils.HandleRequest(req)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func GenerateState() string {
	return guamutils.GenerateRandomString(43, "")
}

func GenereatePKCECodeChallenge(method, verifier string) (string, error) {
	if method != "S256" {
		return "", errors.New("invalid PKCE code challenge method")
	}

	verifiedBuffer := []byte(verifier)
	h := sha256.New()
	_, err := h.Write(verifiedBuffer)
	if err != nil {
		return "", err
	}
	challengeBuffer := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(challengeBuffer), nil
}
