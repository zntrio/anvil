package anvil_test

import (
	"crypto/rand"
	"log"
	"testing"

	"golang.org/x/crypto/salsa20"

	"go.zenithar.org/anvil"
	"go.zenithar.org/anvil/forge"
	"go.zenithar.org/anvil/tap"

	. "github.com/onsi/gomega"
)

func TestForge(t *testing.T) {
	RegisterTestingT(t)

	challenge, sessionId, err := anvil.Forge("toto")
	Expect(err).To(BeNil(), "Error shoul be nil")
	Expect(challenge).ToNot(BeNil(), "Challenge should not be nil")
	Expect(challenge).ToNot(BeEmpty(), "Challenge should not be empty")
	Expect(sessionId).ToNot(BeEmpty(), "Session Id should not be empty")
}

func TestFullChallenge(t *testing.T) {
	RegisterTestingT(t)

	challenge, fsessionId, err := anvil.Forge("toto")
	Expect(err).To(BeNil(), "Error shoul be nil")
	Expect(challenge).ToNot(BeNil(), "Challenge should not be nil")
	Expect(challenge).ToNot(BeEmpty(), "Challenge should not be empty")
	Expect(fsessionId).ToNot(BeEmpty(), "Session Id should not be empty")

	log.Printf("SessionID : %s\n", fsessionId)
	log.Printf("Challenge : %s\n", challenge)

	token, err := anvil.Meld("toto", "foo", challenge)
	Expect(err).To(BeNil(), "Error should be nil")
	Expect(token).ToNot(BeNil(), "Token should not be nil")
	Expect(token).ToNot(BeEmpty(), "Token should not be empty")

	log.Printf("Token : %s\n", token)

	valid, sessionId, principal, err := anvil.Tap(token)
	Expect(err).To(BeNil(), "Error should be nil")
	Expect(valid).To(BeTrue(), "Token tap should be true")
	Expect(principal).To(Equal("toto"), "Principal should equal toto")
	Expect(sessionId).ToNot(BeEmpty(), "Session identifier should not be empty")

	log.Printf("SessionID : %s\n", sessionId)
	Expect(fsessionId).To(Equal(sessionId), "Session Id should be equal")
	log.Printf("Principal : %s\n", principal)
	Expect(principal).To(Equal("toto"), "Principal should equal given one")
}

func TestChallengeEncryptor(t *testing.T) {
	RegisterTestingT(t)

	// Generate a random key
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fail()
	}

	// Generate a nonce
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fail()
	}

	encryptorFunc := func(data []byte) ([]byte, error) {
		// Encrypt stream
		out := make([]byte, len(data))
		salsa20.XORKeyStream(out, data, nonce, &key)
		// Return result
		return out, nil
	}

	decryptorFunc := func(data []byte) ([]byte, error) {
		// Decode stream
		out := make([]byte, len(data))
		salsa20.XORKeyStream(out, data, nonce, &key)
		// Return result
		return out, nil
	}

	challenge, fsessionId, err := anvil.Forge("toto", forge.WithEncryptor(encryptorFunc))
	Expect(err).To(BeNil(), "Error shoul be nil")
	Expect(challenge).ToNot(BeNil(), "Challenge should not be nil")
	Expect(challenge).ToNot(BeEmpty(), "Challenge should not be empty")
	Expect(fsessionId).ToNot(BeEmpty(), "Session Id should not be empty")

	log.Printf("SessionID : %s\n", fsessionId)
	log.Printf("Encrypted Challenge : %s\n", challenge)

	// Challenge must be complete
	token, err := anvil.Meld("toto", "foo", challenge)
	Expect(err).To(BeNil(), "Error should be nil")
	Expect(token).ToNot(BeNil(), "Token should not be nil")
	Expect(token).ToNot(BeEmpty(), "Token should not be empty")

	valid, sessionId, principal, err := anvil.Tap(token, tap.WithDecryptor(decryptorFunc))
	Expect(err).To(BeNil(), "Error should be nil")
	Expect(valid).To(BeTrue(), "Token tap should be true")
	Expect(principal).To(Equal("toto"), "Principal should equal toto")
	Expect(sessionId).ToNot(BeEmpty(), "Session identifier should not be empty")

}
