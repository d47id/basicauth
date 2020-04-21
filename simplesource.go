package basicauth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// SimpleSource takes a single username/password combination and provides an
// AuthSource that returns the password's hash when the username is provided.
// All other usernames will return a non-nil error.
type SimpleSource struct {
	user string
	hash []byte
}

// NewSimpleSource constructs a SimpleSource from the given username and password.
func NewSimpleSource(username, password string) (*SimpleSource, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &SimpleSource{
		user: username,
		hash: hash,
	}, nil
}

// LookupHash implements the AuthSource interface
func (s *SimpleSource) LookupHash(username string) ([]byte, error) {
	if username != s.user {
		return nil, fmt.Errorf("unknown user %s", username)
	}

	return s.hash, nil
}
