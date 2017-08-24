package anvil_test

import (
	"log"
	"testing"

	"go.zenithar.org/anvil"

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
