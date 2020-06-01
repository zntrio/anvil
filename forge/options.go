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

package forge

import (
	"time"

	"github.com/dchest/uniuri"
)

// SessionIDGeneratorFunc is the contract for Session ID generation implementation
type SessionIDGeneratorFunc func() string

// ProcessorFunc contract for challenge pre/post processing
type ProcessorFunc func([]byte) ([]byte, error)

// Options for challenge forging
type Options struct {
	Expiration  time.Duration
	IDGenerator SessionIDGeneratorFunc
	Encryptor   ProcessorFunc
	Decryptor   ProcessorFunc
}

// Option defines forge option contract option function
type Option func(*Options)

// WithExpiration defines the expiration interval
func WithExpiration(expiration time.Duration) Option {
	return func(opts *Options) {
		opts.Expiration = expiration
	}
}

// WithSessionIDGenerator defines the SessionId generation function
func WithSessionIDGenerator(generator SessionIDGeneratorFunc) Option {
	return func(opts *Options) {
		opts.IDGenerator = generator
	}
}

// WithRandomSessionID defines the SessionId generation
func WithRandomSessionID() Option {
	return func(opts *Options) {
		opts.IDGenerator = DefaultSessionGenerator
	}
}

// WithEncryptor defines the challenge encryptor
func WithEncryptor(encryptor ProcessorFunc) Option {
	return func(opts *Options) {
		opts.Encryptor = encryptor
	}
}

// WithDecryptor defines the challenge decryptor
func WithDecryptor(decryptor ProcessorFunc) Option {
	return func(opts *Options) {
		opts.Decryptor = decryptor
	}
}

var (
	// DefaultSessionGenerator defines the default session id generator
	DefaultSessionGenerator = func() string {
		return uniuri.NewLen(64)
	}

	// NoOperationProcessor defines the copy source processor
	NoOperationProcessor = func(payload []byte) ([]byte, error) {
		return payload, nil
	}

	// DefaultEncryptor is the default data encryptor for challenge
	DefaultEncryptor = NoOperationProcessor
)
