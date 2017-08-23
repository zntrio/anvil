package anvil

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/golang/snappy"

	"golang.org/x/crypto/ed25519"
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
func Forge(principal string) (string, error) {
	// Generate a token
	claims := map[string]interface{}{
		"n": uniuri.NewLen(20),
		"i": time.Now().UTC().Unix(),
		"e": time.Now().Add(2 * time.Minute).UTC().Unix(),
		"p": principal,
	}

	// Encode to JSON
	payload, err := json.Marshal(&claims)
	if err != nil {
		return "", fmt.Errorf("anvil: Unable to generate a challenge for given principal, %v", err)
	}

	// Return challenge
	return toOKP(snappy.Encode(nil, payload)), nil
}

// Tap checks for challenge
func Tap(token string) (bool, error) {
	// Split challenge in parts
	parts := strings.SplitN(token, ".", 3)

	// Must have 3 parts (publicKey, challenge, signature)
	if len(parts) != 3 {
		return false, fmt.Errorf("anvil: Invalid challenge, it must contains 3 parts")
	}

	// Decode PublicKey
	publicKeyRaw, err := fromOKP(parts[0])
	if err != nil {
		return false, fmt.Errorf("anvil: Invalid public key, %v", err)
	}
	if len(publicKeyRaw) != ed25519.PublicKeySize {
		return false, fmt.Errorf("anvil: Invalid public key size")
	}

	// Decode challenge
	tokenRaw, err := fromOKP(parts[1])
	if err != nil {
		return false, fmt.Errorf("anvil: Invalid challenge, could not decode body, %v", err)
	}

	// Decode signature
	signatureRaw, err := fromOKP(parts[2])
	if err != nil {
		return false, fmt.Errorf("anvil: Invalid challenge signature encoding, %v", err)
	}
	if len(signatureRaw) != ed25519.SignatureSize {
		return false, fmt.Errorf("anvil: Invalid challenge signature size")
	}

	// Check ed25519 signature
	return ed25519.Verify(publicKeyRaw[:], tokenRaw, signatureRaw), nil
}
