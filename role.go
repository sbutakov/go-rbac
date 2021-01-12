package rbac

import (
	"errors"
	"fmt"
	"math/bits"
)

// Option allows to configure role.
type Option func(*Role) error

// Role represents a role.
type Role struct {
	name      string
	resources map[Resource]AccessLevel
}

// NewRole constructs a role.
func NewRole(name string, options ...Option) (*Role, error) {
	if name == "" {
		return nil, errors.New("empty role name")
	}

	r := &Role{
		name:      name,
		resources: make(map[Resource]AccessLevel),
	}

	for _, option := range options {
		if err := option(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// CanAccess checks whether the role can access the resource.
func (r *Role) CanAccess(resource Resource, mask AccessMask) bool {
	for res, level := range r.resources {
		if res.String() == resource.String() {
			return uint8(mask)&bits.RotateLeft8(1, level.Int()) != 0
		}
	}
	return false
}

// WithResource configures resource with access level.
func WithResource(r Resource, level AccessLevel) Option {
	return func(role *Role) error {
		if r == nil {
			return fmt.Errorf("resource is nil")
		}

		for res := range role.resources {
			if res.String() == r.String() {
				return fmt.Errorf("resource %s is already defined", r.String())
			}
		}

		role.resources[r] = level
		return nil
	}
}
