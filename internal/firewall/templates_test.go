package firewall

import "testing"

func TestTemplateNamesSorted(t *testing.T) {
	names := TemplateNames()
	if len(names) == 0 {
		t.Fatal("no templates")
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("names not sorted: %v", names)
			break
		}
	}
}

func TestGetTemplateKnown(t *testing.T) {
	for _, name := range []string{"ssh-only", "web-server", "postgres", "dns", "ssh-ratelimit", "mesh-only"} {
		rules, ok := GetTemplate(name)
		if !ok {
			t.Errorf("template %q missing", name)
			continue
		}
		if len(rules) == 0 {
			t.Errorf("template %q is empty", name)
		}
		for _, r := range rules {
			if r.Name == "" {
				t.Errorf("template %q has unnamed rule", name)
			}
			if !r.Enabled {
				t.Errorf("template %q has disabled rule", name)
			}
			if r.Action == ActionUnspecified {
				t.Errorf("template %q has unspecified action", name)
			}
		}
	}
}

func TestGetTemplateUnknown(t *testing.T) {
	if _, ok := GetTemplate("does-not-exist"); ok {
		t.Error("expected false for missing template")
	}
}

func TestGetTemplateReturnsCopy(t *testing.T) {
	r1, _ := GetTemplate("ssh-only")
	r2, _ := GetTemplate("ssh-only")
	if &r1[0] == &r2[0] {
		t.Error("template should return independent copies")
	}
	// Mutating one shouldn't change the other.
	r1[0].Name = "mutated"
	if r2[0].Name == "mutated" {
		t.Error("mutation leaked between template callers")
	}
}
