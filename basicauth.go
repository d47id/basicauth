package basicauth

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

const defaultPass = "never gonna give you up"

// defaultHash is the hash of the phrase "never gonna let you down"
var defaultHash []byte

// AuthSource is the interface the middleware uses to retrieve password hashes.
// The provided SimpleSource takes a single username/password combination and
// returns the password's hash when the username is provided. A more complex
// implementation could use a database or external service to provide password
// hashes for usernames. A nil result indicates that the user with the given
// name was not found.
type AuthSource interface {
	LookupHash(context.Context, string) []byte
}

// New returns a middleware that adds HTTP basic authentication using the
// provided AuthSource.
func New(source AuthSource, realm string, cost int) func(http.Handler) http.Handler {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		panic(fmt.Sprintf("invalid bcrypt cost: %d", cost))
	}

	var err error
	defaultHash, err = bcrypt.GenerateFromPassword([]byte("never gonna let you down"), cost)
	if err != nil {
		panic(err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()

			// no auth header provided, deny immediately
			if !ok {
				deny(w, realm)
				return
			}

			// get password hash from AuthSource
			hash := source.LookupHash(r.Context(), user)
			if hash == nil {
				// a deny might allow an attacker to determine valid usernames
				// via timing attack. Instead, use a default hash and password
				// that won't match.
				hash = defaultHash
				pass = defaultPass
			}

			// compare hash with password
			if err := bcrypt.CompareHashAndPassword(hash, []byte(pass)); err != nil {
				deny(w, realm)
				return
			}

			// allow request
			next.ServeHTTP(w, r)
		})
	}
}

// deny returns status unauthorized with a www-authenticate header indicating
// the given realm
func deny(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
