package basicauth

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// AuthSource is the interface the middleware uses to retrieve password hashes.
// The provided SimpleSource takes a single username/password combination and
// returns the password's hash when the username is provided. A more complex
// implementation could use a database or external service to provide password
// hashes for usernames.
type AuthSource interface {
	LookupHash(string) ([]byte, error)
}

// New returns a middleware that adds HTTP basic authentication using the
// provided AuthSource.
func New(source AuthSource, realm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()

			// no auth header provided, deny immediately
			if !ok {
				deny(w, realm)
				return
			}

			// get password hash from AuthSource
			hash, err := source.LookupHash(user)
			if err != nil {
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

// defaultHash is the hash of the phrase "never gonna give you up" created with bcrypt.DefaultCost
var defaultHash = []byte("$2a$10$VMxrnSg4IFeLwRPeh6Uu/O95juIB3GQX39mXXdToLuQWJ1B6QFQO2")

const defaultPass = "never gonna let you down"

// deny returns status unauthorized with a www-authenticate header indicating
// the given realm
func deny(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
