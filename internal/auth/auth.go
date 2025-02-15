package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 15)
	if err != nil {
		fmt.Println("error hashing password", err)
		return "", err
	}
	return string(hashedBytes), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		fmt.Println("password does not match", err)
		return err
	}
	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		fmt.Println("error signing token", err)
		return "", err
	}

	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		fmt.Println("error parsing token", err)
		return uuid.Nil, err
	}
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		idString, err := claims.GetSubject()
		if err != nil {
			fmt.Println("error retrieving userID", err)
			return uuid.Nil, err
		}
		id, err := uuid.Parse(idString)
		if err != nil {
			fmt.Println("error parsing UUID", err)
			return uuid.Nil, err
		}
		return id, nil
	}
	fmt.Println("invalid token", err)
	return uuid.Nil, err
}

func GetApiKey(headers http.Header) (string, error) {
	apiString := headers.Get("Authorization")
	if apiString == "" {
		return "", fmt.Errorf("no token provided")
	}
	stripped := strings.TrimPrefix(apiString, "ApiKey ")
	return stripped, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	tokenString := headers.Get("Authorization")
	if tokenString == "" {
		return "", fmt.Errorf("no token provided")
	}
	stripped := strings.TrimPrefix(tokenString, "Bearer ")
	return stripped, nil
}

func MakeRefreshToken() (string, error) {
	tokenData, err := rand.Read(make([]byte, 32))
	if err != nil {
		fmt.Println("error generating token", err)
		return "", err
	}
	stringified := hex.EncodeToString([]byte(strconv.Itoa(tokenData)))

	return stringified, nil
}
