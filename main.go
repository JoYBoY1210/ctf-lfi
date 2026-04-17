package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

var AdminApiKey string

func init() {

	AdminApiKey = os.Getenv("CTF_CORE_SECRET_KEY")
}

func readHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "Missing 'file' parameter. Example: ?file=public/readme.txt", http.StatusBadRequest)
		return
	}

	if strings.Contains(fileName, "../") || strings.Contains(fileName, "..%2f") {
		http.Error(w, "WAF ALERT: Directory traversal detected. Incident logged.", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile(fileName)
	if err != nil {
		http.Error(w, "file not found: "+err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("X-Powered-By", "Go-Fiber/v2.1")
	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}

func flagHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")

	// Check if the player stole the correct key from the environment
	if apiKey == AdminApiKey {
		fmt.Fprint(w, "Congratulations! Flag: geek{i_am_6atman}\n")
	} else {
		http.Error(w, "Unauthorized. Valid API Key required in X-API-Key header.", http.StatusUnauthorized)
	}
}

func main() {
	http.HandleFunc("/api/read", readHandler)
	http.HandleFunc("/api/flag", flagHandler)

	fmt.Println("Hardened CTF Server running on http://localhost:8080")

	http.ListenAndServe(":8080", nil)
}
