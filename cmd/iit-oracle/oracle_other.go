//go:build !windows

package main

import "errors"

func execute(string, string, request) ([]byte, error) {
	return nil, errors.New("iit-oracle currently requires Windows and a matching IIT DLL")
}
