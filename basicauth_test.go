package basicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBasicAuth(t *testing.T) {
	ss, err := NewSimpleSource("test", "test", bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	mw := New(ss, "test", bcrypt.DefaultCost)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no op
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.SetBasicAuth("no", "match")

	t.Run("unauthorized", func(t *testing.T) {
		handler.ServeHTTP(w, r)
		if code := w.Result().StatusCode; code != http.StatusUnauthorized {
			t.Fatalf("unexpected code: %d %s", code, http.StatusText(code))
		}
	})

	w = httptest.NewRecorder()
	r.SetBasicAuth("test", "test")
	t.Run("authorized", func(t *testing.T) {
		handler.ServeHTTP(w, r)
		if code := w.Result().StatusCode; code != http.StatusOK {
			t.Fatalf("unexpected code: %d %s", code, http.StatusText(code))
		}
	})
}

func BenchmarkBasicAuth(b *testing.B) {
	ss, err := NewSimpleSource("test", "test", bcrypt.DefaultCost)
	if err != nil {
		b.Fatal(err)
	}

	mw := New(ss, "test", bcrypt.DefaultCost)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no op
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.SetBasicAuth("no", "match")

	b.Run("unauthorized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			handler.ServeHTTP(w, r)
		}
	})

	r.SetBasicAuth("test", "test")
	b.Run("authorized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			handler.ServeHTTP(w, r)
		}
	})
}
