package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sekisho.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_Valid(t *testing.T) {
	c, err := Load(write(t, `
listeners:
  - kind: udp
    bind: 0.0.0.0:1620
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Listeners) != 1 || c.Listeners[0].Bind != "0.0.0.0:1620" {
		t.Errorf("Listeners = %+v", c.Listeners)
	}
}

func TestLoad_Errors(t *testing.T) {
	cases := map[string]string{
		"no listeners":     `{}`,
		"unsupported kind": "listeners:\n  - kind: tcp\n    bind: :1\n",
		"missing bind":     "listeners:\n  - kind: udp\n",
		"bad yaml":         `:{`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, content)); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
	if _, err := Load("/nonexistent/sekisho.yaml"); err == nil {
		t.Error("nonexistent file: want error")
	}
}
