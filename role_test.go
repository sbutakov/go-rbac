package rbac

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRole(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		r, err := NewRole("admin")
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			assert.Equal(t, "admin", r.name)
			assert.Empty(t, r.resources)
		}
	})

	t.Run("Configured", func(t *testing.T) {
		resource := bytes.NewBufferString("lib")
		r, err := NewRole("admin", WithResource(resource, AccessNone))
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			assert.Equal(t, r.name, "admin")
			assert.Len(t, r.resources, 1)
			assert.Equal(t, r.resources[resource], AccessNone)
		}
	})

	t.Run("NilResource", func(t *testing.T) {
		r, err := NewRole("admin", WithResource(nil, AccessNone))
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "resource is nil")
		assert.Nil(t, r)
	})

	t.Run("ResourceDuplication", func(t *testing.T) {
		resource := bytes.NewBufferString("lib")
		r, err := NewRole(
			"admin",
			WithResource(resource, AccessRead),
			WithResource(resource, AccessModify),
		)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "already defined")
		assert.Nil(t, r)
	})
}

func TestRole_CanAccess(t *testing.T) {
	resource := bytes.NewBufferString("lib")
	t.Run("ResourceNotFound", func(t *testing.T) {
		r, err := NewRole("", WithResource(resource, AccessDelete))
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			res := bytes.NewBufferString("lib-v2")
			assert.False(t, r.CanAccess(res, MinAccessLevel(AccessRead)))
			assert.False(t, r.CanAccess(res, MinAccessLevel(AccessModify)))
			assert.False(t, r.CanAccess(res, MinAccessLevel(AccessDelete)))
		}
	})

	t.Run("None", func(t *testing.T) {
		r, err := NewRole("", WithResource(resource, AccessNone))
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			assert.False(t, r.CanAccess(resource, MinAccessLevel(AccessRead)))
			assert.False(t, r.CanAccess(resource, MinAccessLevel(AccessModify)))
			assert.False(t, r.CanAccess(resource, MinAccessLevel(AccessDelete)))
		}
	})

	t.Run("Read", func(t *testing.T) {
		r, err := NewRole("", WithResource(resource, AccessRead))
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			assert.True(t, r.CanAccess(resource, MinAccessLevel(AccessRead)))
			assert.False(t, r.CanAccess(resource, MinAccessLevel(AccessModify)))
			assert.False(t, r.CanAccess(resource, MinAccessLevel(AccessDelete)))
		}
	})

	t.Run("Modify", func(t *testing.T) {
		r, err := NewRole("", WithResource(resource, AccessModify))
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			assert.True(t, r.CanAccess(resource, MinAccessLevel(AccessRead)))
			assert.True(t, r.CanAccess(resource, MinAccessLevel(AccessModify)))
			assert.False(t, r.CanAccess(resource, MinAccessLevel(AccessDelete)))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		r, err := NewRole("", WithResource(resource, AccessDelete))
		assert.Nil(t, err)
		if assert.NotNil(t, r) {
			assert.True(t, r.CanAccess(resource, MinAccessLevel(AccessRead)))
			assert.True(t, r.CanAccess(resource, MinAccessLevel(AccessModify)))
			assert.True(t, r.CanAccess(resource, MinAccessLevel(AccessDelete)))
		}
	})
}
