package main

import (
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {
	serveMux := http.NewServeMux()
	filepathRoot := http.Dir(".")
	strippedFileserver := http.StripPrefix("/app", http.FileServer(filepathRoot))
	port := "8080"

	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
	}

	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(strippedFileserver))
	serveMux.HandleFunc("GET /api/healthz", readinessEndpoint)
	serveMux.HandleFunc("GET /api/metrics", metricsReturn(apiCfg))
	serveMux.HandleFunc("POST /api/reset", metricsReset(apiCfg))

	server := &http.Server{
		Addr:    ":" + port,
		Handler: serveMux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(server.ListenAndServe())

}

func readinessEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func metricsReturn(cfg *apiConfig) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits := strconv.Itoa(int(cfg.fileserverHits.Load()))
		body := "Hits: " + hits
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})
}

func metricsReset(cfg *apiConfig) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		cfg.fileserverHits.Swap(0)
	})
}
