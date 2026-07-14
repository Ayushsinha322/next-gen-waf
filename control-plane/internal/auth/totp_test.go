package auth

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, err := b32.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret not base32: %v", err)
	}
	code := hotp(key, uint64(time.Now().Unix()/30))
	if !VerifyTOTP(secret, code) {
		t.Error("valid current code rejected")
	}
	if VerifyTOTP(secret, "12345") {
		t.Error("accepted a 5-digit code")
	}
	if VerifyTOTP(secret, "abcdef") {
		t.Error("accepted a non-numeric code")
	}
	if VerifyTOTP("!!!notbase32", "123456") {
		t.Error("accepted an invalid secret")
	}
	if VerifyTOTP(secret, "") {
		t.Error("accepted an empty code")
	}
}
