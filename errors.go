package anvil

import "errors"

var (
	// ErrExpiredChallenge raised when trying to tap an expired challenge
	ErrExpiredChallenge = errors.New("anvil: Challenge is expired")
)
