package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"testing"
)

func generateRandomSHA256Hash() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(randomBytes)
	hashString := hex.EncodeToString(hash[:])
	return hashString, nil
}

func TestAuthKeyNoHeader(t *testing.T) {

	testRequest := httptest.NewRequest("GET", "/test", nil)

	_, err := GetAPIKey(testRequest.Header)
	if err == nil {
		t.Fatalf("GetAPIKey should have errored")
		return
	}
	if err.Error() != ErrNoAuthHeaderIncluded.Error() {
		t.Fatalf("error should be: %s\n current error: %s", ErrNoAuthHeaderIncluded.Error(), err.Error())
		return

	}

}

func TestAuthKeyMalformed(t *testing.T) {

	hash, _ := generateRandomSHA256Hash()

	testRequest := httptest.NewRequest("GET", "/test", nil)
	testRequest.Header.Set("Authorization", hash)

	_, err := GetAPIKey(testRequest.Header)

	if err == nil {
		t.Fatalf("GetAPIKey should have errored with malformed error")

	}

	if err.Error() != "malformed authorization header" {
		t.Fatalf("error should be malformed error, error returned: %s", err.Error())

	}

}

func TestAuthKeyRetrieve(t *testing.T) {

	expected, _ := generateRandomSHA256Hash()
	apiKey := fmt.Sprintf("ApiKey %s", expected)
	testRequest := httptest.NewRequest("GET", "/test", nil)
	testRequest.Header.Set("Authorization", apiKey)

	result, err := GetAPIKey(testRequest.Header)

	if err != nil {
		t.Fatalf("Error getting api key: %s", err.Error())

	}

	if result != expected {
		t.Fatalf("result auth key: %s does not match expected: %s", result, expected)

	}

}
