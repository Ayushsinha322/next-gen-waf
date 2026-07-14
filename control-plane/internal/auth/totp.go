package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) — hand-rolled on the stdlib so there is no third-party OTP
// dependency. SHA-1, 6 digits, 30s period (what Google Authenticator / Authy /
// 1Password default to).

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh base32-encoded 20-byte secret.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI builds an otpauth:// provisioning URI an authenticator app can scan.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// VerifyTOTP checks a 6-digit code against the secret for the current 30s step,
// allowing ±1 step for clock skew. Constant-time compare on the code.
func VerifyTOTP(secret, code string) bool {
	ok, _ := VerifyTOTPStep(secret, code)
	return ok
}

// VerifyTOTPStep is VerifyTOTP but also returns the matched 30s step counter, so
// callers can BURN a used step to prevent replay of an observed code within the
// ±1 skew window (RFC 6238 §5.2). The step is meaningful only when ok is true.
func VerifyTOTPStep(secret, code string) (ok bool, step int64) {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := b32.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return false, 0
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false, 0
	}
	now := time.Now().Unix() / 30
	for _, w := range []int64{0, -1, 1} {
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(now+w))), []byte(code)) == 1 {
			return true, now + w
		}
	}
	return false, 0
}

// hotp computes the RFC 4226 HOTP value (6 digits) for a counter.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", val%1_000_000)
}
