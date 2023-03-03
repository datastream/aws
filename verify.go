package sign4

// Verify AWS Canonical Request For Signature Version 4

import (
	"errors"
	"net/http"
	"strings"
)

// Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=5a15b22cf462f047318703b92e6f4f38884e4a7ab7b1d6426ca46a8bd1c26cbc
// Authorization: AWS4-HMAC-SHA256 Credential=devops/20180312/hz/dnsapi/aws4_request,SignedHeaders=Content-Length;Content-type;host;x-amz-date,Signature=8a31f6aaa5026579bb2cf20962768190fdd0b4846ed5c48842fa61936245e9c5
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
	items := strings.Split(authHeader, " ")
	var pattens []string
	for _, v := range items {
		v1 := strings.Split(v, ",")
		for _, value := range v1 {
			if len(strings.Trim(value, " ")) == 0 {
				continue
			}
			pattens = append(pattens, strings.Trim(value, " "))
		}
	}
	if len(pattens) != 4 {
		return nil, "", signedHeaders, errors.New("wrong authorization header size")
	}
	signature, err := getCredential(pattens[1])
	if err != nil {
		return nil, "", signedHeaders, errors.New("get authorization header signature failed")
	}
	signedHeaders, err = getSignedHeaders(pattens[2])
	if err != nil {
		return nil, "", signedHeaders, errors.New("get authorization header signedHeaders failed")
	}
	if pattens[3][:9] != "Signature" {
		return nil, "", signedHeaders, errors.New("no signature")
	}
	return signature, authHeader, signedHeaders, nil
}
func getCredential(s string) (*Signature, error) {
	// Check if the credential part has the correct length and format
	if !strings.HasPrefix(s, "Credential=") {
		return nil, errors.New("wrong credential part")
	}
	parts := strings.Split(s[11:], "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return nil, errors.New("wrong credential part")
	}

	// Extract the access key, region, and service from the credential part
	ss := &Signature{
		AccessKey: parts[0],
		Region:    parts[2],
		Service:   parts[3],
	}
	return ss, nil
}
func getSignedHeaders(s string) (map[string]bool, error) {
	// Check if the signed headers part has the correct length and format
	if !strings.HasPrefix(s, "SignedHeaders=") {
		return nil, errors.New("wrong signedheaders part")
	}

	// Extract the signed headers from the input string
	headers := strings.Split(s[14:], ";")

	// Create a map to store the signed headers
	signedHeaders := make(map[string]bool)
	for _, h := range headers {
		signedHeaders[h] = true
	}

	return signedHeaders, nil
}
