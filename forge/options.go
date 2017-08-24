package forge

import (
	"time"

	"github.com/dchest/uniuri"
)

// SessionIDGenerator is the contract for Session ID generation implementation
type SessionIDGenerator func() string

// Options for challenge forging
type Options struct {
	Expiration  time.Duration
	IDGenerator SessionIDGenerator
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
func WithSessionIDGenerator(generator SessionIDGenerator) Option {
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

var (
	// DefaultSessionGenerator defines the default session id generator
	DefaultSessionGenerator = func() string {
		return uniuri.NewLen(64)
	}
)
