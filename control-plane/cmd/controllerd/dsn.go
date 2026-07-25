package main

import (
	"net/url"
	"regexp"
	"strings"
)

// redactedMark is what replaces a secret. Fixed-width so log readers cannot
// infer the password length from the output.
const redactedMark = "****"

// maskPassword redacts the password from a Postgres DSN so the DSN is safe to
// log. It understands both accepted forms:
//
//	URL form:     postgres://user:pass@host:5432/db?sslmode=verify-full
//	keyword form: host=db user=sentinel password=pass sslmode=verify-full
//
// If the DSN cannot be parsed it returns a placeholder rather than the input.
// Echoing an unparsed DSN would defeat the point: that string is precisely the
// one carrying the secret.
//
// This function used to be `return dsn` — a no-op that leaked the full
// credential into the boot log at INFO on every start.
func maskPassword(dsn string) string {
	if dsn == "" {
		return ""
	}

	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "(unparseable DSN redacted)"
		}
		if u.User != nil {
			if _, hasPassword := u.User.Password(); hasPassword {
				u.User = url.UserPassword(u.User.Username(), redactedMark)
			}
		}
		// A password can also ride in the query string.
		if q := u.Query(); q.Has("password") {
			q.Set("password", redactedMark)
			u.RawQuery = q.Encode()
		}
		return u.String()
	}

	// libpq keyword/value form. Split on whitespace and redact the password
	// token, leaving everything else legible for diagnostics.
	fields := strings.Fields(dsn)
	for i, f := range fields {
		if strings.HasPrefix(strings.ToLower(f), "password=") {
			fields[i] = "password=" + redactedMark
		}
	}
	return strings.Join(fields, " ")
}

// credentialInURL matches the "user:secret@" component of any URL embedded in a
// larger string, capturing the username so it can be preserved.
var credentialInURL = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/?#\s]+):[^@/?#\s]*@`)

// passwordKeyword matches a libpq-style `password=value` token.
var passwordKeyword = regexp.MustCompile(`(?i)password=[^\s]*`)

// redactCredentials scrubs anything that looks like an embedded credential from
// arbitrary text.
//
// Driver errors are not under our control: a connection failure can quote the
// DSN it failed to parse or dial, which would put the password in the log even
// though we never asked for it. Every error that might carry a DSN goes through
// here before it reaches the logger.
func redactCredentials(s string) string {
	if s == "" {
		return ""
	}
	s = credentialInURL.ReplaceAllString(s, "$1:"+redactedMark+"@")
	return passwordKeyword.ReplaceAllString(s, "password="+redactedMark)
}

// safeErr returns err's message with any embedded credential redacted, for use
// with zap.String("error", safeErr(err)) in place of zap.Error(err) on paths
// where the error may quote a DSN.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	return redactCredentials(err.Error())
}
