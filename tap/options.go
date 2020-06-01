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

package tap

// ProcessorFunc contract for challenge pre/post processing
type ProcessorFunc func([]byte) ([]byte, error)

// Options for challenge forging
type Options struct {
	Decryptor ProcessorFunc
}

// Option defines forge option contract option function
type Option func(*Options)

// WithDecryptor defines the challenge decryptor
func WithDecryptor(decryptor ProcessorFunc) Option {
	return func(opts *Options) {
		opts.Decryptor = decryptor
	}
}

var (
	// NoOperationProcessor defines the copy source processor
	NoOperationProcessor = func(payload []byte) ([]byte, error) {
		return payload, nil
	}

	// DefaultDecryptor is the default data decryptor for challenge
	DefaultDecryptor = NoOperationProcessor
)
