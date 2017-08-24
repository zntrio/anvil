package internal

import "time"

// IsExpired retruns the challenge expiration status
func (ch *Challenge) IsExpired() bool {
	return time.Now().UTC().After(time.Unix(ch.Expiration, 0).UTC())
}
