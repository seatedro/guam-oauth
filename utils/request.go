package utils

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type ResponseBody map[string]any

func HandleRequest(req http.Request) (*[]byte, error) {
	req.Header.Set("User-Agent", "guam")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(&req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("received non-success response status: %s", resp.Status)
	}

	// var response ResponseBody
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// err = json.Unmarshal(body, &response)
	// if err != nil {
	// 	return nil, err
	// }

	return &body, nil
}

func CreateURL(rawURL string, urlSearchParams map[string]*string) (*url.URL, error) {
	newURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	q := newURL.Query()
	for key, value := range urlSearchParams {
		if value != nil {
			q.Set(key, *value)
		}
	}
	newURL.RawQuery = q.Encode()

	return newURL, nil
}

type HeaderType int

const (
	AUTHORIZATION_HEADER_TYPE_BEARER HeaderType = iota
	AUTHORIZATION_HEADER_TYPE_BASIC
)

func AuthorizationHeader(t HeaderType, token string) (string, error) {
	if t == AUTHORIZATION_HEADER_TYPE_BEARER {
		return "Bearer " + token, nil
	}
	if t == AUTHORIZATION_HEADER_TYPE_BASIC {
		return "Basic " + token, nil
	}

	return "", errors.New("invalid token type")
}
