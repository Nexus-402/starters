// A complete Nexus402 creator endpoint for Go. Standard library only.
//
// Set four environment variables, put it behind HTTPS, and publish its URL.
// `../starters_test.go` builds this kit from an empty directory, exactly as a
// creator downloads it, and drives it with the gateway's REAL signer.
//
// The gateway answers `initialize`, `tools/list` and notifications itself,
// from the description and input schema you publish; only `tools/call`
// reaches you, already charged.
//
//	PORT                    where to listen (default 8080)
//	NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
//	NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
//	NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
//	                        (GET https://api.nexus402.dev/v1/signing-key lists them)
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// The gateway's own cap on a request body. Anything larger did not come from it.
const maxBodyBytes = 10 << 20

// runTool is YOUR TOOLS. tool is the last segment of the published name
// (`acme/text@v2/word_count` arrives as `word_count`).
//
// Return the status and the bare MCP result. The gateway wraps the result in
// the JSON-RPC envelope, so your own envelope would nest. `isError: true` is
// still a CHARGED call: use it only when the caller's input made your tool fail
// after it did work. When your tool itself fails, return a 5xx; when the
// request is wrong before any work, a 4xx. Both refund the caller.
func runTool(tool string, args map[string]any) (int, any) {
	switch tool {
	case "word_count":
		text, _ := args["text"].(string)
		words := len(strings.Fields(text))
		return http.StatusOK, map[string]any{"content": []map[string]string{{"type": "text", "text": strconv.Itoa(words)}}}
	default:
		return http.StatusNotFound, map[string]string{"error": "unknown tool " + tool}
	}
}

type endpoint struct {
	verifier Verifier
}

func (e endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	verdict, err := e.verifier.Verify(r, body, time.Now())
	if err != nil {
		// No detail in the body: a reason tells a prober how close they are.
		log.Printf("refused: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// The proof goes on EVERY answer to a verified request, errors included,
	// and BEFORE WriteHeader: a header set afterwards is dropped in silence.
	w.Header().Set("X-Nexus-Proof", verdict.Proof)
	w.Header().Set("Content-Type", "application/json")

	// THE HELLO: answer with the proof and run nothing.
	if verdict.Hello {
		w.WriteHeader(http.StatusOK)
		return
	}

	var call struct {
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &call); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "body is not JSON"})
		return
	}
	name := call.Params.Name
	status, result := runTool(name[strings.LastIndex(name, "/")+1:], call.Params.Arguments)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}

func required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is not set", name)
	}
	return value
}

func main() {
	keys, err := ParsePublicKeys(required("NEXUS_PUBLIC_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	verifier := Verifier{
		RegisteredHost: required("NEXUS_REGISTERED_HOST"),
		CreatorKey:     required("NEXUS_CREATOR_KEY"),
		PublicKeys:     keys,
	}
	port := 8080
	if raw := os.Getenv("PORT"); raw != "" {
		port, err = strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			log.Fatal("PORT must be a number between 1 and 65535")
		}
	}

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           endpoint{verifier: verifier},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      130 * time.Second,
	}
	log.Printf("listening on :%d", port)
	log.Fatal(server.ListenAndServe())
}
