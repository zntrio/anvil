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
