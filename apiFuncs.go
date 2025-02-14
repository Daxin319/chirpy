package main

import (
	"context"
	"fmt"
	"html/template"
	"main/internal/auth"
	"main/internal/database"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	queries        *database.Queries
	platform       string
	tokenSecret    string
}

type hitCounter struct {
	Hits string
}

type parameters struct {
	Body             string    `json:"body"`
	Email            string    `json:"email"`
	Password         string    `json:"password"`
	UserID           uuid.UUID `json:"user_id"`
	ChirpID          uuid.UUID `json:"chirp_id"`
	ExpiresInSeconds int       `json:"expires_in_seconds"`
}

type Token struct {
	TokenString string `json:"token"`
}

type chirp struct {
	ID         uuid.UUID `json:"id"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	Body       string    `json:"body"`
	UserID     uuid.UUID `json:"user_id"`
}

type User struct {
	ID              uuid.UUID `json:"id"`
	Created_at      time.Time `json:"created_at"`
	Updated_at      time.Time `json:"updated_at"`
	Email           string    `json:"email"`
	Hashed_password string    `json:"hashed_password"`
	Token           string    `json:"token"`
	Refresh_token   string    `json:"refresh_token"`
}

type returnVals struct {
	Error   string `json:"error"`
	Cleaned string `json:"cleaned_body"`
}

func (p *parameters) cleanInput() *parameters {
	bannedWords := []string{"kerfuffle", "sharbert", "fornax"}
	origInput := strings.Split(p.Body, " ")

	for i, word := range origInput {
		for _, bannedWord := range bannedWords {
			if bannedWord == strings.ToLower(word) {
				origInput[i] = "****"
			}
		}
	}
	p.Body = strings.Join(origInput, " ")
	return p
}

func (cfg *apiConfig) createChirpEndpoint(w http.ResponseWriter, r *http.Request) {
	params := getRequestParams(w, r)
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 500, "error getting bearer token")
	}
	id, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		respondWithError(w, 401, "unauthorized request")
	}
	args := database.CreateChirpParams{
		Body:   params.cleanInput().Body,
		UserID: id,
	}

	w.Header().Set("Content-Type", "application/json")

	if len(params.Body) > 140 {
		respondWithError(w, 400, "chirp too long")
	} else if len(params.Body) == 0 {
		respondWithError(w, 400, "cannot send empty chirp")
	} else {

		chirp, err := cfg.queries.CreateChirp(context.Background(), args)
		if err != nil {
			fmt.Println("error creating chirp", err)
			w.WriteHeader(500)
		}
		respondWithJSON(w, http.StatusCreated, &chirp, make([]string, 0))
	}
}

func (cfg *apiConfig) createUserEndpoint(w http.ResponseWriter, r *http.Request) {
	params := getRequestParams(w, r)

	hashed, err := auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println("error hashing password", err)
		w.WriteHeader(500)
		return
	}

	args := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashed,
	}

	w.Header().Set("Content-Type", "application/json")

	user, err := cfg.queries.CreateUser(context.Background(), args)
	if err != nil {
		fmt.Println("error creating user", err)
		w.WriteHeader(500)
		return
	}
	respondWithJSON(w, http.StatusCreated, &user, make([]string, 0))
}

func (cfg *apiConfig) getAllChirpsEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	allChirps, err := cfg.queries.GetAllChirps(context.Background())
	if err != nil {
		fmt.Println("error pulling chirps", err)
		w.WriteHeader(500)
		return
	}
	mappedChirps := mapChirps(allChirps)
	respondWithJSON(w, http.StatusOK, &mappedChirps, make([]string, 0))
}

func (cfg *apiConfig) getSingleChirp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	chirpID := r.PathValue("chirpID")
	parsedID, err := uuid.Parse(chirpID)
	if err != nil {
		fmt.Println("error formatting chirpID", err)
		w.WriteHeader(500)
		return
	}
	data, err := cfg.queries.GetOneChirp(context.Background(), parsedID)
	if err != nil {
		fmt.Println("chirp not found", err)
		w.WriteHeader(404)
		return
	}
	respondWithJSON(w, http.StatusOK, &data, make([]string, 0))
}

func (cfg *apiConfig) loginEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := getRequestParams(w, r)

	user, err := cfg.queries.GetUserByEmail(context.Background(), params.Email)
	if err != nil {
		respondWithError(w, 404, "no matching user found")
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, 401, "invalid email or password")
	} else {
		var tokens []string
		token, err := auth.MakeJWT(user.ID, cfg.tokenSecret, 1*time.Hour)
		if err != nil {
			respondWithError(w, 500, "error creating JWT")
		}
		tokens = append(tokens, token)
		refresh_token, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, 500, "error generating refresh token")
		}
		args := database.CreateRefreshTokenParams{
			Token:  refresh_token,
			UserID: user.ID,
		}

		_ = cfg.queries.CreateRefreshToken(context.Background(), args)

		tokens = append(tokens, refresh_token)

		respondWithJSON(w, 200, &user, tokens)
	}

}
func (cfg *apiConfig) refreshEndpoint(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 500, "error getting bearer token")
	}
	validated, err := cfg.queries.ValidateRefreshToken(context.Background(), tokenString)
	if err != nil {
		respondWithError(w, 401, "unauthorized token")
	}
	if validated.RevokedAt.Valid {
		respondWithError(w, 401, "expired token")
	}
	user, err := cfg.queries.GetUserFromRefreshToken(context.Background(), validated.Token)
	if err != nil {
		respondWithError(w, 500, "error getting user data from database")
	}
	newTokenString, err := auth.MakeJWT(user.ID, cfg.tokenSecret, 1*time.Hour)
	if err != nil {
		respondWithError(w, 500, "error creating auth token")
	}
	tokenStruct := Token{
		TokenString: newTokenString,
	}
	respondWithJSON(w, 200, tokenStruct, make([]string, 0))
}

func (cfg *apiConfig) revokeEndpoint(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 500, "error getting bearer token")
	}
	validated, err := cfg.queries.ValidateRefreshToken(context.Background(), tokenString)
	if err != nil {
		respondWithError(w, 401, "unauthorized token")
	}
	_ = cfg.queries.RevokeToken(context.Background(), validated.Token)
	respondWithJSON(w, 204, validated.Token, make([]string, 0))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func metricsReturn(cfg *apiConfig) func(http.ResponseWriter, *http.Request) {
	adminTmpl := template.Must(template.ParseFiles("admin/metrics/index.html"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits := strconv.Itoa(int(cfg.fileserverHits.Load()))
		counter := hitCounter{
			Hits: hits,
		}
		adminTmpl.Execute(w, counter)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	})
}

func reset(cfg *apiConfig) func(http.ResponseWriter, *http.Request) {
	if cfg.platform != "dev" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := cfg.queries.ResetUsers(context.Background())
		if err != nil {
			fmt.Println("error resetting users", err)
			return
		}
		cfg.fileserverHits.Swap(0)
	})
}
