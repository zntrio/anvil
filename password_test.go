package anvil_test

import (
	"testing"

	"go.zenithar.org/anvil"

	. "github.com/onsi/gomega"
)

func TestPasswordSeal(t *testing.T) {
	RegisterTestingT(t)

	publicKey, err := anvil.Seal("toto", "foo")
	Expect(err).To(BeNil(), "Error should be nil")
	Expect(publicKey).ToNot(BeNil(), "PublicKey should not be nil")
	Expect(publicKey).ToNot(BeEmpty(), "PublicKey should not be blank")
	Expect(publicKey).To(Equal("qrK4RAzbzEJ5w2wuObrFjNivdaI-mMoPJhqxRfkqDt0"))
}
