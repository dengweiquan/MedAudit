package main

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"medaudit/internal/platform"
)

// registerAlertRoutes 告警：
//   - GET  /api/v1/alerts            未确认告警（?all=1 含已确认）
//   - POST /api/v1/alerts/{id}/ack   确认（已知悉）
func registerAlertRoutes(mux *http.ServeMux, db *sql.DB, sessions *platform.SessionStore) {
	mux.HandleFunc("/api/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := platform.ListAlerts(db, r.URL.Query().Get("all") != "1")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, items)
	})
	mux.HandleFunc("/api/v1/alerts/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
		if r.Method != http.MethodPost || !strings.HasSuffix(rest, "/ack") {
			http.NotFound(w, r)
			return
		}
		id, err := strconv.ParseInt(strings.TrimSuffix(rest, "/ack"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if err := platform.AckAlert(db, id, currentUser(r, sessions)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
}
