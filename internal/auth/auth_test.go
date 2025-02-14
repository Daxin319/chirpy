package auth_test

import (
	"net/http"
	"testing"
	"time"

	"main/internal/auth"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func generateJWT(userID uuid.UUID, expiresIn time.Duration, secret string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func TestJWTValidation(t *testing.T) {
	tokenSecret := "supersecretkey"
	wrongSecret := "wrongsecret"
	userID := uuid.New()

	// ✅ Test: Valid token
	validToken, err := generateJWT(userID, time.Minute*15, tokenSecret)
	if err != nil {
		t.Fatalf("failed to generate valid token: %v", err)
	}
	parsedUserID, err := auth.ValidateJWT(validToken, tokenSecret)
	if err != nil {
		t.Errorf("valid token should pass, but got error: %v", err)
	}
	if parsedUserID != userID {
		t.Errorf("expected userID %v, got %v", userID, parsedUserID)
	}

	// ❌ Test: Expired token
	expiredToken, err := generateJWT(userID, -time.Minute*5, tokenSecret) // Expired 5 minutes ago
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}
	_, err = auth.ValidateJWT(expiredToken, tokenSecret)
	if err == nil {
		t.Errorf("expired token should be rejected")
	}

	// ❌ Test: Token signed with wrong secret
	wrongSecretToken, err := generateJWT(userID, time.Minute*15, wrongSecret)
	if err != nil {
		t.Fatalf("failed to generate token with wrong secret: %v", err)
	}
	_, err = auth.ValidateJWT(wrongSecretToken, tokenSecret)
	if err == nil {
		t.Errorf("token signed with wrong secret should be rejected")
	}

	// ❌ Test: Malformed token (random string)
	_, err = auth.ValidateJWT("invalid.token.string", tokenSecret)
	if err == nil {
		t.Errorf("malformed token should be rejected")
	}

	// ❌ Test: Token missing the Subject field
	claims := jwt.RegisteredClaims{
		Issuer:   "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	missingSubjectToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("failed to generate token without subject: %v", err)
	}
	_, err = auth.ValidateJWT(missingSubjectToken, tokenSecret)
	if err == nil {
		t.Errorf("token without a subject should be rejected")
	}
}
func TestGetBearerToken(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "Bearer ahgaowhgjoashljghaopsdghjlkajsfdhgla;hsfdg")

	expected := "ahgaowhgjoashljghaopsdghjlkajsfdhgla;hsfdg"

	token, err := auth.GetBearerToken(header)
	if err != nil {
		t.Errorf("failed to strip prefix %v", err)
	}
	if token != expected {
		t.Errorf("failed to strip prefix, token does not match: expected %s, got %v", expected, token)
	}

	header.Set("Authorization", "Bearer theWitchKingofAngmar")
	expected = "theWitchKingofAngmar"

	token, err = auth.GetBearerToken(header)
	if err != nil {
		t.Errorf("failed to strip prefix %v", err)
	}
	if token != expected {
		t.Errorf("invalid token returned, expected %s, got %v", expected, token)
	}

	header.Set("Authorization", "")

	token, err = auth.GetBearerToken(header)
	if err == nil {
		t.Errorf("header with no auth field should error")
	}
}
