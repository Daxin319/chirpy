package main

import (
	"database/sql"
	"fmt"
	"log"
	"main/internal/database"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("failed to load env file", err)
		os.Exit(1)
	}

	dbUrl := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		fmt.Println("error connecting to database", err)
		os.Exit(1)
	}

	secret := os.Getenv("SECRET")
	dbQueries := database.New(db)

	userPlatform := os.Getenv("PLATFORM")
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		queries:        dbQueries,
		platform:       userPlatform,
		tokenSecret:    secret,
	}

	serveMux := http.NewServeMux()
	filepathRoot := http.Dir(".")
	strippedFileserver := http.StripPrefix("/app", http.FileServer(filepathRoot))
	port := "8080"

	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(strippedFileserver))
	serveMux.HandleFunc("GET /api/healthz", readinessEndpoint)
	serveMux.HandleFunc("GET /admin/metrics", metricsReturn(apiCfg))
	serveMux.HandleFunc("POST /admin/reset", reset(apiCfg))
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpEndpoint)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsEndpoint)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getSingleChirp)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUserEndpoint)
	serveMux.HandleFunc("PUT /api/users", apiCfg.resetCredentials)
	serveMux.HandleFunc("POST /api/login", apiCfg.loginEndpoint)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.refreshEndpoint)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeEndpoint)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: serveMux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(server.ListenAndServe())

}
