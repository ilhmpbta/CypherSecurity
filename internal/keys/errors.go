package keys

import "errors"

var (
	ErrNoKeypair     = errors.New("keys: no keypair found for user")
	ErrSessionLocked = errors.New("keys: session locked (re-auth required)")
)
