package main

import (
	"encoding/json"
	"fmt"
	"main/internal/database"
	"net/http"
)

func readinessEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func getRequestParams(w http.ResponseWriter, r *http.Request) parameters {
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println("error unmarshaling json", err)
		w.WriteHeader(500)
		return parameters{}
	}
	return params
}

func mapChirps(chirpList []database.Chirp) []chirp {
	mappedChirps := []chirp{}
	for _, post := range chirpList {
		mappedChirps = append(mappedChirps, chirp{
			ID:         post.ID,
			Created_at: post.CreatedAt,
			Updated_at: post.UpdatedAt,
			Body:       post.Body,
			UserID:     post.UserID,
		})
	}
	return mappedChirps
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respBody := returnVals{
		Error: message,
	}

	data, err := json.Marshal(respBody)
	if err != nil {
		fmt.Println("error marshaling json", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}, tokens []string) {
	switch v := payload.(type) {
	case *database.Chirp:
		respBody := chirp{
			ID:         v.ID,
			Created_at: v.CreatedAt,
			Updated_at: v.UpdatedAt,
			Body:       v.Body,
			UserID:     v.UserID,
		}

		data, err := json.Marshal(respBody)
		if err != nil {
			fmt.Println("error marshaling json", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(code)
		w.Write(data)
	case *database.User:
		user := User{
			ID:            v.ID,
			Created_at:    v.CreatedAt,
			Updated_at:    v.UpdatedAt,
			Email:         v.Email,
			Is_chirpy_red: v.IsChirpyRed.Bool,
		}

		if len(tokens) == 2 {
			user.Token = tokens[0]
			user.Refresh_token = tokens[1]
		}

		data, err := json.Marshal(user)
		if err != nil {
			fmt.Println("error marshaling json", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(code)
		w.Write(data)
	case *[]chirp:
		data, err := json.Marshal(v)
		if err != nil {
			fmt.Println("error marshaling json", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(code)
		w.Write(data)
	case Token:
		data, err := json.Marshal(v)
		if err != nil {
			fmt.Println("error marshaling json", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(code)
		w.Write(data)
	default:
		w.WriteHeader(code)
	}
}
