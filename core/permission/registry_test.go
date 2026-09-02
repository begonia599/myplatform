package permission

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

// newMemoryService builds a PermissionService on an in-memory enforcer (no
// DB, no adapter) so policy-seeding behaviour can be tested in isolation.
func newMemoryService(t *testing.T) *PermissionService {
	t.Helper()
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		t.Fatalf("parse model: %v", err)
	}
	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	return &PermissionService{enforcer: e, cfg: &PermissionConfig{}}
}

func TestSeedGrants_OnlyNamespacedObjects(t *testing.T) {
	svc := newMemoryService(t)

	svc.seedGrants("blog", []RoleGrant{
		{Role: "user", Resource: "comment", Action: "create"},
		{Role: "editor", Resource: "article", Action: "update"},
		{Role: "", Resource: "comment", Action: "read"},       // skipped
		{Role: "user", Resource: "", Action: "read"},          // skipped
		{Role: "user", Resource: "comment", Action: ""},       // skipped
		{Role: "user", Resource: "comment", Action: "create"}, // duplicate, idempotent
	})

	policies, err := svc.enforcer.GetPolicy()
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected exactly 2 policies, got %d: %v", len(policies), policies)
	}
	for _, p := range policies {
		if len(p[1]) < len("blog.") || p[1][:len("blog.")] != "blog." {
			t.Fatalf("policy object %q is not namespaced under blog.", p[1])
		}
	}

	if ok, _ := svc.enforcer.Enforce("user", "blog.comment", "create"); !ok {
		t.Fatal("declared grant user→blog.comment/create should be allowed")
	}
	if ok, _ := svc.enforcer.Enforce("editor", "blog.article", "update"); !ok {
		t.Fatal("declared grant editor→blog.article/update should be allowed")
	}
}

// A module declaring a resource that happens to share a name with a platform
// object (storage, imagebed, …) must not grant anything on that platform
// object. This is the regression test for the removed auto-seeding of
// un-namespaced admin/user policies.
func TestSeedGrants_CannotReachPlatformObjects(t *testing.T) {
	svc := newMemoryService(t)

	svc.seedGrants("evil", []RoleGrant{
		{Role: "user", Resource: "storage", Action: "delete"},
		{Role: "user", Resource: "imagebed", Action: "upload"},
	})

	for _, c := range [][3]string{
		{"user", "storage", "delete"},
		{"user", "imagebed", "upload"},
		{"admin", "storage", "delete"},
	} {
		if ok, _ := svc.enforcer.Enforce(c[0], c[1], c[2]); ok {
			t.Fatalf("grant leaked onto platform object: %v", c)
		}
	}
	// …but the namespaced form is, as declared.
	if ok, _ := svc.enforcer.Enforce("user", "evil.storage", "delete"); !ok {
		t.Fatal("namespaced grant should be allowed")
	}
}
