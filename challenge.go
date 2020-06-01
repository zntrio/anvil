// Licensed to Anvil under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Anvil licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package anvil

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"

	"zntr.io/anvil/forge"
	"zntr.io/anvil/internal"
	"zntr.io/anvil/tap"
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
		Encryptor:   forge.DefaultEncryptor,
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
	if err != nil {
		return "", "", fmt.Errorf("anvil: Unable to marshal challenge, %v", err)
	}

	// Pass to encryptor
	content, err := dopts.Encryptor(payload)
	if err != nil {
		return "", "", fmt.Errorf("anvil: Unable to encrypt challenge, %v", err)
	}

	// Return challenge
	return toOKP(content), challenge.SessionId, err
}

// Tap checks for challenge
func Tap(token string, opts ...tap.Option) (bool, string, string, error) {
	// Default settings
	dopts := tap.Options{
		Decryptor: tap.DefaultDecryptor,
	}

	// Apply Options
	for _, o := range opts {
		o(&dopts)
	}

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

	// Preporcess tokenRaw
	content, err := dopts.Decryptor(tokenRaw)
	if err != nil {
		return false, "", "", fmt.Errorf("anvil: Invalid challenge encoding, %v", err)
	}

	// Umarshal challenge
	var challenge internal.Challenge
	err = internal.Unmarshal(content, &challenge)
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
