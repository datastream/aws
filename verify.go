package sign4

// Verify AWS Canonical Request For Signature Version 4

import (
	"errors"
	"net/http"
	"strings"
)

// Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=5a15b22cf462f047318703b92e6f4f38884e4a7ab7b1d6426ca46a8bd1c26cbc
func GetSignature(r *http.Request) (*Signature, string, map[string]bool, error) {
	authHeader := r.Header.Get("Authorization")
	return GetSignatureFromString(authHeader)
}

func GetSignatureFromString(authHeader string) (*Signature, string, map[string]bool, error) {
	signedHeaders := make(map[string]bool)
	if len(authHeader) < 16 {
		return nil, "", signedHeaders, errors.New("get authorization header failed")
	}
	if authHeader[:16] != "AWS4-HMAC-SHA256" {
		return nil, "", signedHeaders, errors.New("get aws4-hmac-sha256 failed")
	}
	pattens := strings.Split(authHeader, " ")
	if len(pattens) != 4 {
		return nil, "", signedHeaders, errors.New("wrong authorization header size")
	}
	signature, err := getCredential(pattens[1][:len(pattens[1])-1])
	if err != nil {
		return nil, "", signedHeaders, errors.New("get authorization header signature failed")
	}
	signedHeaders, err = getSignedHeaders(pattens[2][:len(pattens[2])-1])
	if err != nil {
		return nil, "", signedHeaders, errors.New("get authorization header signedHeaders failed")
	}
	if pattens[3][:9] != "Signature" {
		return nil, "", signedHeaders, errors.New("no signature")
	}
	return signature, authHeader, signedHeaders, nil
}
func GetCredentialFromString(authHeader string) (*Signature, error) {
	if len(authHeader) < 16 {
		return nil, errors.New("bad authorization header")
	}
	if authHeader[:16] != "AWS4-HMAC-SHA256" {
		return nil, errors.New("not aws4-hmac-sha256")
	}
	pattens := strings.Split(authHeader, " ")
	if len(pattens) != 4 {
		return nil, errors.New("wrong authorization header size")
	}
	return getCredential(pattens[1][:len(pattens[1])-1])
}

func GetSignedHeadersFromString(authHeader string) (string, error) {
	if len(authHeader) < 16 {
		return "", errors.New("bad authorization header")
	}
	if authHeader[:16] != "AWS4-HMAC-SHA256" {
		return "", errors.New("not aws4-hmac-sha256")
	}
	pattens := strings.Split(authHeader, " ")
	if len(pattens) != 4 {
		return "", errors.New("wrong authorization header size")
	}
	if len(pattens[1]) < 14 {
		return "", errors.New("wrong signedheaders part")
	}
	if pattens[1][:14] != "SignedHeaders=" {
		return "", errors.New("wrong signedheaders part")
	}

	return pattens[1][14:], nil
}
func getCredential(s string) (*Signature, error) {
	if len(s) < 11 {
		return nil, errors.New("wrong credential part")
	}
	if s[:11] != "Credential=" {
		return nil, errors.New("wrong credential part")
	}
	parts := strings.Split(s[11:], "/")
	if len(parts) != 5 {
		return nil, errors.New("wrong credential part")
	}
	if parts[4] != "aws4_request" {
		return nil, errors.New("wrong credential part")
	}
	ss := &Signature{
		AccessKey: parts[0],
		Region:    parts[2],
		Service:   parts[3],
	}
	return ss, nil
}

func getSignedHeaders(s string) (map[string]bool, error) {
	h := make(map[string]bool)
	if len(s) < 14 {
		return h, errors.New("wrong signedheaders part")
	}
	if s[:14] != "SignedHeaders=" {
		return h, errors.New("wrong signedheaders part")
	}
	headers := strings.Split(s[14:], ";")
	for _, v := range headers {
		h[v] = true
	}
	return h, nil
}
