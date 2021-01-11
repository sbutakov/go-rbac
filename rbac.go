// Package rbac provides methods to limit access based on roles and access levels.
package rbac

import (
	"fmt"
	"math/bits"
	"sync"
)

type (
	// AccessMask unsigned 8-bit permission mask.
	AccessMask uint8
	// AccessLevel is permission set.
	AccessLevel int
)

// Int returns integer access level representation.
func (a AccessLevel) Int() int {
	return int(a)
}

const (
	// AccessNone is an access level that denies all.
	AccessNone AccessLevel = 0x0
	// AccessRead is an access level that allows read only.
	AccessRead AccessLevel = 0x2
	// AccessModify is an access level that allows read and modify.
	AccessModify AccessLevel = 0x4
	// AccessDelete is an access level that allows read, modify and delete.
	AccessDelete AccessLevel = 0x7
)

// Resource is an interface which should be protected.
type Resource interface {
	fmt.Stringer
}

// Module contains roles.
type Module struct {
	roles map[string]*Role
	mu    sync.RWMutex
}

// New constructs a new module instance.
func New(roles ...*Role) (*Module, error) {
	m := &Module{roles: make(map[string]*Role)}
	for _, role := range roles {
		if _, ok := m.roles[role.name]; ok {
			return nil, fmt.Errorf("role %s is redeclared", role.name)
		}
		m.roles[role.name] = role
	}

	return m, nil
}

// AddRole checks whether the role is already defined, either add a new one.
func (m *Module) AddRole(r *Role) error {
	m.mu.RLock()
	if _, ok := m.roles[r.name]; ok {
		m.mu.RUnlock()
		return fmt.Errorf("role %s is already defined", r.name)
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.roles[r.name] = r

	return nil
}

// FindRole finds role by name, if it's not found returns nil.
func (m *Module) FindRole(name string) *Role {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if role, ok := m.roles[name]; ok {
		return role
	}

	return nil
}

// MinAccessLevel makes an access mask with minimal access level.
func MinAccessLevel(level AccessLevel) AccessMask {
	return AccessMask(^(bits.RotateLeft8(1, level.Int()) - 1))
}
