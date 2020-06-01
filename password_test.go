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

package anvil_test

import (
	"testing"

	"zntr.io/anvil"

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
