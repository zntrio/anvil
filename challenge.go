package anvil

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"

	"go.zenithar.org/anvil/forge"
	"go.zenithar.org/anvil/internal"
)

var (
	// ErrExpiredChallenge raised when trying to tap an expired challenge
	ErrExpiredChallenge = errors.New("anvil: Challenge is expired")
)

// Meld a challenge from given credentials
func Meld(principal, password, challenge string) (string, error) {
	// Derive password to get keys
	pub, priv, err := derivePassword([]byte(principal), []byte(password))
	if err != nil {
		return "", err
	}
	// Decode challenge
	challengeRaw, err := fromOKP(challenge)
	if err != nil {
		return "", fmt.Errorf("anvil: Unable to decode challenge, %v", err)
	}

	// Sign challenge with private key
	signatureRaw := ed25519.Sign(priv, challengeRaw)

	// Return token
	return fmt.Sprintf("%s.%s.%s", toOKP(pub), challenge, toOKP(signatureRaw)), nil
}

// Forge a challenge
func Forge(principal string, opts ...forge.Option) (string, string, error) {
	// Default Setings
	dopts := &forge.Options{
		IDGenerator: forge.DefaultSessionGenerator,
		Expiration:  2 * time.Minute,
	}

	// Apply param functions
	for _, o := range opts {
		o(dopts)
	}

	// Build the challenge
	challenge := internal.Challenge{
		SessionId:  dopts.IDGenerator(),
		Principal:  principal,
		IssuedAt:   time.Now().UTC().Unix(),
		Expiration: time.Now().Add(dopts.Expiration).UTC().Unix(),
	}

	// Marshal challenge
	payload, err := internal.Marshal(&challenge)

	// Return challenge
	return payload, challenge.SessionId, err
}

// Tap checks for challenge
func Tap(token string) (bool, string, string, error) {
	// Split challenge in parts
	parts := strings.SplitN(token, ".", 3)

	// Must have 3 parts (publicKey, challenge, signature)
	if len(parts) != 3 {
		return false, "", "", fmt.Errorf("anvil: Invalid challenge, it must contains 3 parts")
	}

	// Decode PublicKey
	publicKeyRaw, err := fromOKP(parts[0])
	if err != nil {
		return false, "", "", fmt.Errorf("anvil: Invalid public key, %v", err)
	}
	if len(publicKeyRaw) != ed25519.PublicKeySize {
		return false, "", "", fmt.Errorf("anvil: Invalid public key size")
	}

	// Decode challenge
	tokenRaw, err := fromOKP(parts[1])
	if err != nil {
		return false, "", "", fmt.Errorf("anvil: Unable to decode challenge, %v", err)
	}

	// Decode signature
	signatureRaw, err := fromOKP(parts[2])
	if err != nil {
		return false, "", "", fmt.Errorf("anvil: Invalid challenge signature encoding, %v", err)
	}
	if len(signatureRaw) != ed25519.SignatureSize {
		return false, "", "", fmt.Errorf("anvil: Invalid challenge signature size")
	}

	// Umarshal challenge
	var challenge internal.Challenge
	err = internal.Unmarshal(parts[1], &challenge)
	if err != nil {
		return false, "", "", fmt.Errorf("anvil: Unable to unmarshall challenge, %v", err)
	}

	// Check challenge expiration
	if challenge.IsExpired() {
		return false, challenge.SessionId, challenge.Principal, ErrExpiredChallenge
	}

	// Check ed25519 signature
	return ed25519.Verify(publicKeyRaw[:], tokenRaw, signatureRaw), challenge.SessionId, challenge.Principal, nil
}
