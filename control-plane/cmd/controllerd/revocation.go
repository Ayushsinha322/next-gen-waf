package main

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// revocationCheckTimeout bounds the denylist lookup made for every
// authenticated request.
const revocationCheckTimeout = 2 * time.Second

// revocationChecker adapts the store's denylist lookup to the JWT service.
//
// The lookup runs on EVERY authenticated call, and it used to run under
// context.Background(): when Postgres stalled — or the pool had no free
// connection — each API call blocked in its auth middleware for as long as the
// stall lasted, before the handler's own deadline could apply. The console hung
// instead of failing.
//
// The policy on failure is unchanged: fail OPEN (a database blip must not log
// everyone out). A timeout is one more failure of that kind — and it now takes
// two seconds to reach instead of never arriving.
func revocationChecker(
	isRevoked func(ctx context.Context, jti string) (bool, error),
	timeout time.Duration,
	log *zap.Logger,
) func(jti string) bool {
	return func(jti string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		revoked, err := isRevoked(ctx, jti)
		if err != nil {
			log.Warn("token revocation check failed (fail-open)", zap.Error(err))
			return false
		}
		return revoked
	}
}
