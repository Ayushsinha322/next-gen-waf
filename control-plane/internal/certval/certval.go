// Package certval validates an uploaded TLS certificate + private key before it
// is installed as the management-console certificate. It performs the full set
// of checks the data plane does NOT do today: the key actually matches the cert,
// the cert is currently valid (not expired / not yet valid), it has at least one
// SAN, and — when a CA bundle is supplied — that the chain verifies. Hostname
// mismatch and a missing chain are returned as non-fatal warnings.
//
// Security: this package never logs PEM material and never returns the private
// key. Callers must likewise avoid logging the raw PEM.
package certval

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Result is the validated metadata extracted from the certificate. It is safe
// to surface to the UI and to persist (no private material).
type Result struct {
	Subject           string   `json:"subject"`
	Issuer            string   `json:"issuer"`
	SANs              []string `json:"san"`
	NotBefore         int64    `json:"not_before"`
	NotAfter          int64    `json:"not_after"`
	DaysRemaining     int64    `json:"days_remaining"`
	FingerprintSHA256 string   `json:"fingerprint"` // hex, lower-case, of the leaf DER
	KeyType           string   `json:"key_type"`    // "ECDSA P-256", "RSA 2048", "Ed25519"
	SelfSigned        bool     `json:"self_signed"`
	Warnings          []string `json:"warnings"`
}

// Validate performs hard + soft validation. A non-nil error means the cert must
// be REJECTED (hard failure). A nil error with Result.Warnings populated means
// the cert is acceptable but the operator should be told about the warnings.
//
//   - certPEM / keyPEM:  the leaf cert (optionally followed by intermediates) + key
//   - caBundlePEM:       optional roots/intermediates for chain verification ("" = skip, warn)
//   - expectedHost:      optional hostname/IP to check against the SANs ("" = skip)
func Validate(certPEM, keyPEM, caBundlePEM, expectedHost string) (*Result, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" {
		return nil, fmt.Errorf("certificate is empty")
	}
	if keyPEM == "" {
		return nil, fmt.Errorf("private key is empty")
	}

	// (1)+(2)+(3): parse cert, parse key, and verify the key MATCHES the cert.
	// tls.X509KeyPair does all three in one shot — it fails if either is
	// unparseable or if the private key does not correspond to the leaf cert's
	// public key.
	keyPair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate and private key are invalid or do not match: %w", err)
	}
	if len(keyPair.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in PEM")
	}

	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}

	now := time.Now()
	res := &Result{
		Subject:           leaf.Subject.CommonName,
		Issuer:            leaf.Issuer.CommonName,
		SANs:              sansOf(leaf),
		NotBefore:         leaf.NotBefore.Unix(),
		NotAfter:          leaf.NotAfter.Unix(),
		DaysRemaining:     int64(leaf.NotAfter.Sub(now).Hours() / 24),
		FingerprintSHA256: fingerprint(leaf.Raw),
		KeyType:           keyType(leaf),
		SelfSigned:        leaf.Subject.String() == leaf.Issuer.String(),
	}
	if res.Subject == "" {
		// Fall back to the full DN when there's no CN, so the UI shows something.
		res.Subject = leaf.Subject.String()
	}

	// (4) not-before: certificate must already be valid.
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid yet (valid from %s)", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	// (5) not-after: certificate must not be expired.
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate has expired (expired %s)", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	// (6) SAN presence: modern browsers ignore the CN, so a cert with no SAN is useless.
	if len(res.SANs) == 0 {
		return nil, fmt.Errorf("certificate has no Subject Alternative Names (SAN) — it will be rejected by browsers")
	}

	// (7) chain validation against a supplied CA bundle (hard error if it fails).
	if strings.TrimSpace(caBundlePEM) != "" {
		if err := verifyChain(leaf, keyPair.Certificate[1:], caBundlePEM, now); err != nil {
			return nil, fmt.Errorf("certificate chain does not verify against the supplied CA bundle: %w", err)
		}
	} else if !res.SelfSigned {
		res.Warnings = append(res.Warnings,
			"no CA bundle provided — the certificate chain was not verified; clients may see an incomplete-chain error if intermediates are missing")
	}

	// (8) hostname / SAN match — a WARNING, not a hard failure (management may be
	// reached by IP, by an internal name, or by several names).
	if h := strings.TrimSpace(expectedHost); h != "" {
		if err := leaf.VerifyHostname(h); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("certificate is not valid for %q (SANs: %s) — browsers will warn on a hostname mismatch", h, strings.Join(res.SANs, ", ")))
		}
	}

	// Expiry heads-up.
	if res.DaysRemaining < 30 {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("certificate expires in %d day(s) — plan a rotation", res.DaysRemaining))
	}
	if res.SelfSigned {
		res.Warnings = append(res.Warnings,
			"certificate is self-signed — browsers will warn unless this CA/cert is imported into the client trust store")
	}

	// Key strength: hard-fail clearly broken RSA keys, warn on marginal ones.
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
		bits := pub.N.BitLen()
		if bits < 1024 {
			return nil, fmt.Errorf("RSA key is only %d bits — far too weak; use at least 2048-bit RSA", bits)
		}
		if bits < 2048 {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RSA key is only %d bits — below the recommended 2048-bit minimum", bits))
		}
	}

	return res, nil
}

func sansOf(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses))
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func keyType(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// verifyChain builds an intermediate pool from any certs that followed the leaf
// in the PEM, a root pool from the supplied CA bundle, and verifies the leaf.
func verifyChain(leaf *x509.Certificate, intermediateDER [][]byte, caBundlePEM string, now time.Time) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caBundlePEM)) {
		return fmt.Errorf("CA bundle contains no valid PEM certificates")
	}
	inter := x509.NewCertPool()
	for _, der := range intermediateDER {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}
