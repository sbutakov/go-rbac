package rbac

import "net/http"

// AuthorizedRole is a HTTP-header value that contains RBAC role.
const AuthorizedRole = "Authorized-Role"

// Middleware is a middleware type.
type Middleware func(http.Handler) http.Handler

// GuardHTTPMiddleware guards HTTP-resource with minimal access level.
func (m *Module) GuardHTTPMiddleware(resource Resource, minimal AccessLevel) Middleware {
	mask := MinAccessLevel(minimal)
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			name := r.Header.Get(AuthorizedRole)
			if name == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			role := m.FindRole(name)
			if role == nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if !role.CanAccess(resource, mask) {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
