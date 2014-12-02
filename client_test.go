package veritas

import (
	"testing"
)

func TestRequestSignature(t *testing.T) {
	const expected = "b17f4169e26d7ac3a8457af62c4c8824ad88ef0c49f4eb666c936157405f44a99d1a2ffef0f5e4f5f3a6350d8fba98c720deb0be60600c138d5055fe66f1b72c"

	client := NewClient(1, 1, "test")
	signature := client.signRequest("GET", "/asdf", "body-here")

	if signature != expected {
		t.Errorf("signature expected '%s' but was '%s'", expected, signature)
	}
}
