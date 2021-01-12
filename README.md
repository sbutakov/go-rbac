[![Build Status](https://www.travis-ci.com/sbutakov/go-rbac.svg?branch=main)](https://www.travis-ci.com/sbutakov/go-rbac)
[![codecov](https://codecov.io/gh/sbutakov/go-rbac/branch/main/graph/badge.svg?token=2PLX7SWZ1K)](https://codecov.io/gh/sbutakov/go-rbac)

# Golang RBAC library

RBAC is an approach to control access based on roles. Roles allow access to resources with a defined access level. This golang library provides methods to manage roles with access levels to protect resources.

## Access level

The access mask manages access control. Mask is presented as an unsigned 8-bit value. There are a few access levels ordered by privilege levels, e.g., the most significant access level `AccessDelete` inherits the lower access level.

The following is a list of access levels:

* `AccessNone` – denies any access.
* `AccessRead` – allows access to read.
* `AccessModify` – allows access to read and modify.
* `AccessDelete` – allows access to read, modify and delete.

## Install

```bash
go get -u github.com/sbutakov/go-rbac
```

## Run linter

```bash
make lint
```

## Run tests

```bash
make test
```

## Example

The following example shows how to manage HTTP endpoints access based on roles with this library.

```go
package main

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/sbutakov/go-rbac"
)

// Article is a representation of RBAC resource.
// Any object which fits fmt.Stringer can be used as an RBAC resource.
type Article struct {
}

func (Article) String() string {
	return "article"
}

func main() {
	// Define the role that allows reading the resource.
	reader, _ := rbac.NewRole("reader", rbac.WithResource(Article{}, rbac.AccessRead))
	// Define the role that allows modifying and reading.
	author, _ := rbac.NewRole("author", rbac.WithResource(Article{}, rbac.AccessModify))

	// RBAC initializing. Also, roles can be passed through constructor, like this New(role1, ...).
	accessControl, _ := rbac.New()
	_ = accessControl.AddRole(reader)
	_ = accessControl.AddRole(author)

	// Feel free to use another router if you prefer.
	r := chi.NewRouter()
	r.Route("/v1/articles", func(r chi.Router) {
		// Define group endpoints that allow to read the resource.
		r.Group(func(r chi.Router) {
			// This middleware protects endpoints group with rbac.AccessRead as a minimal access level.
			// Middleware extracts role name from Authorized-Role HTTP-header value.
			// If the role either is not found or non-existence or has an insufficient access level
			// to reach the resource, the middleware returns 403 HTTP status code.
			r.Use(accessControl.GuardHTTPMiddleware(Article{}, rbac.AccessRead))

			// In this case, the resource can be reach both defined role.
			r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
		})

		// Define group endpoints that allow modify the resource.
		r.Group(func(r chi.Router) {
			// This middleware protects endpoints group with rbac.AccessModify as a minimal access level.
			r.Use(accessControl.GuardHTTPMiddleware(Article{}, rbac.AccessModify))

			// In this case, "author" can reach this resource.
			r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
			})
		})
	})
}

```
### Results

Let's request endpoints and see the results. The first request has no role at all.

```bash
curl -i localhost:8080/v1/articles
HTTP/1.1 403 Forbidden
Date: Tue, 12 Jan 2021 05:54:33 GMT
Content-Length: 0
```

As we can see, the request is forbidden because the resource is protected, but the request is not authorized and has no role with sufficient permission to reach this.

The next request tries to reach the resource to read it with role "reader," which has sufficient access level to read it.

```bash
curl -i localhost:8080/v1/articles -H 'Authorized-Role: reader'
HTTP/1.1 200 OK
Date: Tue, 12 Jan 2021 05:55:28 GMT
Content-Length: 0
```

This request tries to modify the resource with role "reader" which has an insufficient access level to reach the goal.

```bash
curl -iX POST localhost:8080/v1/articles -H 'Authorized-Role: reader'
HTTP/1.1 403 Forbidden
Date: Tue, 12 Jan 2021 05:55:56 GMT
Content-Length: 0
```

The request with the role "author" tries to modify the resource. This request is allowed because the role has a sufficient access level.

```
curl -iX POST localhost:8080/v1/articles -H 'Authorized-Role: author'
HTTP/1.1 201 Created
Date: Tue, 12 Jan 2021 05:56:17 GMT
Content-Length: 0
```

