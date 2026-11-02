package main

import "testing"

func TestSplitKeyArgument(t *testing.T) {
	for _, tc := range []struct{ name, input, path, password string }{
		{"relative", "key.dat:secret", "key.dat", "secret"},
		{"windows", "C:\\keys\\Key-6.dat", "C:\\keys\\Key-6.dat", ""},
		{"windows password", "C:\\keys\\Key-6.dat:secret:part", "C:\\keys\\Key-6.dat", "secret:part"},
		{"forward slashes", "D:/keys/key.dat:pass", "D:/keys/key.dat", "pass"},
		{"unix", "/keys/key.dat:pass", "/keys/key.dat", "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s := splitKeyArgument(tc.input)
			if p != tc.path || s != tc.password {
				t.Fatalf("unexpected parsed path/password")
			}
		})
	}
}
