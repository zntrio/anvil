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
	"bytes"
	"encoding/base64"
	"fmt"
	"math"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

// Derive password using Blake2s+scrypt as HKDF
func derivePassword(principal, password []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	// Hash password using Blake2s (32byte)
	key := blake2s.Sum256([]byte(password))
	salt := []byte(principal)
	N := int(math.Pow(2, 17)) // CPU/Cost
	r := 8
	p := 1
	keyLen := 64

	// Prepare scrypt derivation for Ed25519 key generation
	keyRaw, err := scrypt.Key(key[:], salt, N, r, p, keyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("anvil: Unable to derive password, scrypt error: %v", err)
	}

	// Build ed25519 keys
	read := bytes.NewReader(keyRaw)
	pub, priv, err := ed25519.GenerateKey(read)
	if err != nil {
		return nil, nil, fmt.Errorf("anvil: Unable to generate Ed25519 key pair, %v", err)
	}

	// Return keys
	return pub, priv, nil
}

// Export as OKP representation
func toOKP(content []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(content)
}

// Import from OKP representation
func fromOKP(content string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(content)
}
