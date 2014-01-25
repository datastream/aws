package sign4_test

import (
	"../aws"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestGenerateSigningKey(t *testing.T) {
	s := sign4.Signature{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "host",
	}
	tt, _ := time.Parse(time.RFC1123, "Mon, 09 Sep 2011 23:36:00 GMT")
	k, err := sign4.GenerateSigningKey(s.SecretKey, s.Region, s.Service, tt)
	if err != nil {
		t.Fatal("failed to generate signing key", string(k))
	}
	if fmt.Sprintf("%x", k) != "e220a8ee99f059729066fd06efe5c0f949d6aa8973360d189dd0e0eddd7a9596" {
		t.Fatal("wrong key")
	}
}

func TestCredentailScope(t *testing.T) {
	s := sign4.Signature{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "host",
	}
	tt, _ := time.Parse(time.RFC1123, "Mon, 09 Sep 2011 23:36:00 GMT")
	credentialScope := sign4.CredentialScope(tt, s.Region, s.Service)
	if credentialScope != "20110909/us-east-1/host/aws4_request" {
		t.Fatal("wrong credentialscope")
	}
}

func TestCanonicalRequest(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://host.foo.com/%20/foo", nil)
	r.Header.Add("date", "Mon, 09 Sep 2011 23:36:00 GMT")
	v, _ := sign4.CanonicalRequest(r)
	if v != `GET
/%20/foo

date:Mon, 09 Sep 2011 23:36:00 GMT
host:host.foo.com

date;host
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` {
		t.Fatal("wrong canonicalrequest")
	}
}

func TestStringToSign(t *testing.T) {
	s := sign4.Signature{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "host",
	}
	r, _ := http.NewRequest("GET", "http://host.foo.com/%20/foo", nil)
	r.Header.Add("date", "Mon, 09 Sep 2011 23:36:00 GMT")
	canonicalRequest, _ := sign4.CanonicalRequest(r)
	tt, _ := time.Parse(time.RFC1123, "Mon, 09 Sep 2011 23:36:00 GMT")
	credentialScope := sign4.CredentialScope(tt, s.Region, s.Service)
	stringToSign := sign4.StringToSign(canonicalRequest, credentialScope, tt)
	if stringToSign != `AWS4-HMAC-SHA256
20110909T233600Z
20110909/us-east-1/host/aws4_request
69c45fb9fe3fd76442b5086e50b2e9fec8298358da957b293ef26e506fdfb54b` {
		fmt.Println(stringToSign)
	}
}

func TestAuthHeader(t *testing.T) {
	s := sign4.Signature{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "host",
	}
	r, _ := http.NewRequest("GET", "http://host.foo.com/%20/foo", nil)
	r.Header.Add("date", "Mon, 09 Sep 2011 23:36:00 GMT")
	s.SignRequest(r)
	if r.Header.Get("authorization") != `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=f309cfbd10197a230c42dd17dbf5cca8a0722564cb40a872d25623cfa758e374` {
		t.Fatal(r.Header.Get("authorization"), "miss match")
	}
}

func TestPostHeader(t *testing.T) {
	s := sign4.Signature{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "host",
	}
	r, _ := http.NewRequest("POST", "http://host.foo.com/", ioutil.NopCloser(bytes.NewBuffer([]byte("foo=bar"))))
	r.Header.Add("date", "Mon, 09 Sep 2011 23:36:00 GMT")
	r.Header.Add("content-type", "application/x-www-form-urlencoded; charset=utf8")
	s.SignRequest(r)
	if r.Header.Get("authorization") != `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=b105eb10c6d318d2294de9d49dd8b031b55e3c3fe139f2e637da70511e9e7b71` {
		t.Fatal(r.Header.Get("authorization"), "miss match")
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Fatal("http body error")
	}
	if string(b) != "foo=bar" {
		t.Fatal("wrong body")
	}
}
