package rbac

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

type Article struct{}

func (Article) String() string {
	return "article"
}

func TestModule_GuardHTTPMiddleware(t *testing.T) {
	m, err := New()
	assert.Nil(t, err)
	assert.NotNil(t, m)

	mux := chi.NewMux()
	mux.Group(func(r chi.Router) {
		// AccessModify protects these group endpoints as a minimal access level.
		// To reach these resources, a role must have an access level greater or equal to AccessModify.
		r.Use(m.GuardHTTPMiddleware(Article{}, AccessModify))
		r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	assert.Nil(t, err)
	assert.NotNil(t, req)

	t.Run("StatusOK", func(t *testing.T) { // nolint: dupl
		// Request with "author" role tries to reach the resource with AccessModify access level.
		// Since AccessModify protects the resource as minimal access level, the role has enough
		// permission to reach the resource.

		role, err := NewRole("author", WithResource(Article{}, AccessModify))
		assert.Nil(t, err)
		assert.NotNil(t, role)
		assert.Nil(t, m.AddRole(role))

		req.Header.Set(AuthorizedRole, "author")
		resp, err := http.DefaultClient.Do(req)
		assert.Nil(t, err)
		assert.NotNil(t, resp)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("StatusForbidden", func(t *testing.T) { // nolint: dupl
		// Request with "reader" role tries to reach the resource with AccessModify access level.
		// Since AccessModify protects the resource as minimal access level, the role has insufficient
		// permission to reach the resource.

		role, err := NewRole("reader", WithResource(Article{}, AccessRead))
		assert.Nil(t, err)
		assert.NotNil(t, role)
		assert.Nil(t, m.AddRole(role))

		req.Header.Set(AuthorizedRole, "reader")
		resp, err := http.DefaultClient.Do(req)
		assert.Nil(t, err)
		assert.NotNil(t, resp)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("WithoutRole", func(t *testing.T) {
		resp, err := http.DefaultClient.Do(req)
		assert.Nil(t, err)
		assert.NotNil(t, resp)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("EmptyRole", func(t *testing.T) {
		req.Header.Set(AuthorizedRole, "")
		resp, err := http.DefaultClient.Do(req)
		assert.Nil(t, err)
		assert.NotNil(t, resp)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("RoleNotFound", func(t *testing.T) {
		req.Header.Set(AuthorizedRole, "another")
		resp, err := http.DefaultClient.Do(req)
		assert.Nil(t, err)
		assert.NotNil(t, resp)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})
}
