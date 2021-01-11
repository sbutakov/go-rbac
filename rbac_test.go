package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		m, err := New()
		assert.Nil(t, err)
		if assert.NotNil(t, m) {
			assert.Empty(t, m.roles)
		}
	})

	t.Run("WithRole", func(t *testing.T) {
		role, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, role)

		m, err := New(role)
		assert.Nil(t, err)
		if assert.NotNil(t, m) {
			assert.Len(t, m.roles, 1)
			assert.Equal(t, m.roles[role.name], role)
		}
	})

	t.Run("RoleRedeclaration", func(t *testing.T) {
		role, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, role)

		redeclare, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, redeclare)

		m, err := New(role, redeclare)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "role admin is redeclared")
		assert.Nil(t, m)
	})
}

func TestModule_AddRole(t *testing.T) {
	t.Run("EmptyModule", func(t *testing.T) {
		role, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, role)

		m, err := New()
		assert.Nil(t, err)
		if assert.NotNil(t, m) {
			assert.Nil(t, m.AddRole(role))
			assert.Len(t, m.roles, 1)
		}
	})

	t.Run("NotEmptyModule", func(t *testing.T) {
		role, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, role)

		m, err := New(role)
		assert.Nil(t, err)
		if assert.NotNil(t, m) {
			assert.Len(t, m.roles, 1)
		}

		another, err := NewRole("user")
		assert.Nil(t, err)
		assert.NotNil(t, another)
		if assert.Nil(t, m.AddRole(another)) {
			assert.Len(t, m.roles, 2)
			assert.Equal(t, m.roles[role.name], role)
			assert.Equal(t, m.roles[another.name], another)
		}
	})

	t.Run("RedeclareRole", func(t *testing.T) {
		role, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, role)

		m, err := New(role)
		assert.Nil(t, err)
		assert.NotNil(t, m)

		redeclare, err := NewRole("admin")
		assert.Nil(t, err)
		assert.NotNil(t, role)
		err = m.AddRole(redeclare)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "role admin is already defined")
	})
}

func TestModule_FindRole(t *testing.T) {
	role, err := NewRole("admin")
	assert.Nil(t, err)
	assert.NotNil(t, role)

	m, err := New(role)
	assert.Nil(t, err)
	assert.NotNil(t, m)

	assert.Equal(t, m.FindRole("admin"), role)
	assert.Nil(t, m.FindRole("another"))
}
