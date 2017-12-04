package sign4_test

import (
	"../aws"
	"net/http"
	"testing"
)

func TestVerify(t *testing.T) {
	s := sign4.Signature{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "host",
	}
	r, _ := http.NewRequest("GET", "http://host.foo.com/%20/foo", nil)
	r.Header.Add("date", "Mon, 09 Sep 2011 23:36:00 GMT")
	s.SignRequest(r, make(map[string]bool))
	r.Header.Add("x-data", "testmemmmm")
	authheader := r.Header.Get("authorization")
	ss, aa, ah, err := sign4.GetSignature(r)
	if err != nil {
		t.Fatal("failed to get signature")
	}
	if ss.AccessKey != s.AccessKey || ss.Region != s.Region || ss.Service != s.Service {
		t.Fatal("failed to get signature", ss.AccessKey, ss.Region, ss.Service)
	}
	if aa != authheader {
		t.Fatal("wrong authorization header", aa)
	}
	r.Header.Del("x-data")
	r.Header.Del("authorization")
	s.SignRequest(r, ah)
	ss, aa, ah, err = sign4.GetSignature(r)
	t.Log(r)
	if err != nil {
		t.Fatal("failed to get signature")
	}
	if ss.AccessKey != s.AccessKey || ss.Region != s.Region || ss.Service != s.Service {
		t.Fatal("failed to get signature", ss.AccessKey, ss.Region, ss.Service)
	}
	t.Log(aa)
	t.Log(authheader)
	if aa != authheader {
		t.Fatal("wrong authorization header", aa)
	}
}
