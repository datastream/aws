package sign4

// AWS Canonical Request For Signature Version 4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// BasicDateFormat and BasicDateFormatShort define aws-date format
const (
	BasicDateFormat      = "20060102T150405Z"
	BasicDateFormatShort = "20060102"
)

func hmacsha256(key []byte, data string) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(key))
	if _, err := h.Write([]byte(data)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Build a CanonicalRequest from a regular request string
//
// See http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
// CanonicalRequest =
//  HTTPRequestMethod + '\n' +
//  CanonicalURI + '\n' +
//  CanonicalQueryString + '\n' +
//  CanonicalHeaders + '\n' +
//  SignedHeaders + '\n' +
//  HexEncode(Hash(RequestPayload))
func CanonicalRequest(r *http.Request, signedHeaders map[string]bool) (string, error) {
	data, err := RequestPayload(r)
	if err != nil {
		return "", err
	}
	hexencode, err := HexEncodeSHA256Hash(data)
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", r.Method, CanonicalURI(r), CanonicalQueryString(r), CanonicalHeaders(r, signedHeaders), SignedHeaders(r, signedHeaders), hexencode), err
}

// CanonicalURI return request uri
func CanonicalURI(r *http.Request) string {
	pattens := strings.Split(r.URL.Path, "/")
	var uri []string
	for _, v := range pattens {
		switch v {
		case "":
			continue
		case ".":
			continue
		case "..":
			if len(uri) > 0 {
				uri = uri[:len(uri)-1]
			}
		default:
			uri = append(uri, url.QueryEscape(v))
		}
	}
	urlpath := "/" + strings.Join(uri, "/")
	return fmt.Sprintf("%s", strings.Replace(urlpath, "+", "%20", -1))
}

// CanonicalQueryString
func CanonicalQueryString(r *http.Request) string {
	var a []string
	for key, value := range r.URL.Query() {
		k := url.QueryEscape(key)
		for _, v := range value {
			var kv string
			if v == "" {
				kv = k
			} else {
				kv = fmt.Sprintf("%s=%s", k, url.QueryEscape(v))
			}
			a = append(a, strings.Replace(kv, "+", "%20", -1))
		}
	}
	sort.Strings(a)
	return fmt.Sprintf("%s", strings.Join(a, "&"))
}

// CanonicalHeaders
func CanonicalHeaders(r *http.Request, signedHeaders map[string]bool) string {
	var a []string
	for key, value := range r.Header {
		if len(signedHeaders) == 0 || signedHeaders[strings.ToLower(key)] {

			sort.Strings(value)
			var q []string
			for _, v := range value {
				q = append(q, trimString(v))
			}
			a = append(a, strings.ToLower(key)+":"+strings.Join(q, ","))
		}
	}
	if r.Header.Get("host") == "" || !signedHeaders["host"] {
		a = append(a, "host:"+r.Host)
	}
	sort.Strings(a)
	return fmt.Sprintf("%s\n", strings.Join(a, "\n"))
}

// SignedHeaders
func SignedHeaders(r *http.Request, signedHeaders map[string]bool) string {
	var a []string
	for key := range r.Header {
		if len(signedHeaders) == 0 || signedHeaders[strings.ToLower(key)] {
			a = append(a, strings.ToLower(key))
		}
	}
	if r.Header.Get("host") == "" || !signedHeaders["host"] {
		a = append(a, "host")
	}
	sort.Strings(a)
	return fmt.Sprintf("%s", strings.Join(a, ";"))
}

// RequestPayload
func RequestPayload(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte(""), nil
	}
	b, err := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	return b, err
}

// Return the Credential Scope. See http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
func CredentialScope(t time.Time, regionName, serviceName string) string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", t.UTC().Format(BasicDateFormatShort), regionName, serviceName)
}

// Create a "String to Sign". See http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
func StringToSign(canonicalRequest, credentialScope string, t time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(canonicalRequest))
	return fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%x",
		t.UTC().Format(BasicDateFormat), credentialScope, hash.Sum(nil))
}

// Generate a "signing key" to sign the "String To Sign". See http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
func GenerateSigningKey(secretKey, regionName, serviceName string, t time.Time) ([]byte, error) {

	key := []byte("AWS4" + secretKey)
	var err error
	dateStamp := t.UTC().Format(BasicDateFormatShort)
	data := []string{dateStamp, regionName, serviceName, "aws4_request"}
	for _, d := range data {
		key, err = hmacsha256(key, d)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

// Create the AWS Signature Version 4. See http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
func SignStringToSign(stringToSign string, signingKey []byte) (string, error) {
	hm, err := hmacsha256(signingKey, stringToSign)
	return fmt.Sprintf("%x", hm), err
}

// HexEncodeSHA256Hash return hexcode of sha256
func HexEncodeSHA256Hash(body []byte) (string, error) {
	hash := sha256.New()
	if body == nil {
		body = []byte("")
	}
	_, err := hash.Write(body)
	return fmt.Sprintf("%x", hash.Sum(nil)), err
}

// Get the finalized value for the "Authorization" header. The signature parameter is the output from SignStringToSign
func AuthHeaderValue(signature, accessKey, credentialScope, signedHeaders string) string {
	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", accessKey, credentialScope, signedHeaders, signature)
}

func trimString(s string) string {
	var trimedString []byte
	inQuote := false
	var lastChar byte
	s = strings.TrimSpace(s)
	for _, v := range []byte(s) {
		if byte(v) == byte('"') {
			inQuote = !inQuote
		}
		if lastChar == byte(' ') && byte(v) == byte(' ') && !inQuote {
			continue
		}
		trimedString = append(trimedString, v)
		lastChar = v
	}
	return string(trimedString)
}

// Signature AWS meta
type Signature struct {
	AccessKey string
	SecretKey string
	Region    string
	Service   string
}

// SignRequest set Authorization header
func (s *Signature) SignRequest(r *http.Request, signedHeaders map[string]bool) error {
	var t time.Time
	var err error
	var dt string
	if dt = r.Header.Get("x-amz-date"); dt != "" {
		t, err = time.Parse(BasicDateFormat, dt)
	} else if dt = r.Header.Get("date"); dt != "" {
		t, err = time.Parse(time.RFC1123, dt)
	}
	if err != nil || dt == "" {
		r.Header.Del("date")
		t = time.Now()
		r.Header.Set("x-amz-date", t.UTC().Format(BasicDateFormat))
	}
	canonicalRequest, err := CanonicalRequest(r, signedHeaders)
	if err != nil {
		return err
	}
	credentialScope := CredentialScope(t, s.Region, s.Service)
	stringToSign := StringToSign(canonicalRequest, credentialScope, t)
	key, err := GenerateSigningKey(s.SecretKey, s.Region, s.Service, t)
	if err != nil {
		return err
	}
	signature, err := SignStringToSign(stringToSign, key)
	if err != nil {
		return err
	}
	signedHeadersstring := SignedHeaders(r, signedHeaders)
	authValue := AuthHeaderValue(signature, s.AccessKey, credentialScope, signedHeadersstring)
	r.Header.Set("Authorization", authValue)
	return nil
}

func (s *Signature) GetStringToSign(r *http.Request, signedHeaders map[string]bool) (*string, error) {
	var t time.Time
	var err error
	var dt string
	if dt = r.Header.Get("x-amz-date"); dt != "" {
		t, err = time.Parse(BasicDateFormat, dt)
	}
	if err != nil || dt == "" {
		return nil, fmt.Errorf("fail to get date")
	}
	canonicalRequest, err := CanonicalRequest(r, signedHeaders)
	if err != nil {
		return nil, err
	}
	credentialScope := CredentialScope(t, s.Region, s.Service)
	stringToSign := StringToSign(canonicalRequest, credentialScope, t)
	return &stringToSign, nil
}
