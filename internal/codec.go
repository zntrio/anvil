package internal

import (
	"github.com/gogo/protobuf/proto"
)

// Marshal converts a protobuf message to a URL legal string.
func Marshal(message proto.Message) ([]byte, error) {
	data, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Unmarshal decodes a protobuf message.
func Unmarshal(data []byte, message proto.Message) error {
	return proto.Unmarshal(data, message)
}
