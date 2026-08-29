// Package adminapi, admin domain servisini bir HTTP/JSON API olarak dışa açar.
//
// Kimlik doğrulama: /api/login parolayı (Argon2id) doğrular ve HMAC-imzalı,
// durumsuz bir oturum token'ı döner. Korumalı uçlar "Authorization: Bearer
// <token>" bekler. Yetki (RBAC) admin domain servisinde uygulanır.
package adminapi

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminread"
	"xdr.corp/suite/server/internal/security"
)

//go:embed console.html
var consoleHTML []byte

// AuthStore, e-postadan yönetici kimliği + parola hash'i çözer.
type AuthStore interface {
	LookupAdmin(ctx context.Context, email string) (adminID, passwordHash string, err error)
}

// Server, admin HTTP API'sidir.
type Server struct {
	adminSvc *admin.Service
	reader   *adminread.Service
	auth     AuthStore
	sessions *security.SessionSigner
	ttl      time.Duration
	now      func() time.Time
}

// New oluşturur.
func New(adminSvc *admin.Service, reader *adminread.Service, auth AuthStore, sessions *security.SessionSigner, ttl time.Duration) *Server {
	return &Server{adminSvc: adminSvc, reader: reader, auth: auth, sessions: sessions, ttl: ttl, now: time.Now}
}

// Handler, yönlendirmeleri kayıtlı bir http.Handler döner.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Web yönetim konsolu (aynı köken — API çağrıları CORS'suz çalışır).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		// Konsol self-contained (inline stil+script, dış kaynak yok); CSP bunu
		// yansıtır ve aynı kökene kısıtlar.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(consoleHTML)
	})
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/enrollment-tokens", s.authed(s.handleIssueToken))
	mux.HandleFunc("POST /api/devices/quarantine", s.authed(s.handleQuarantine))
	mux.HandleFunc("POST /api/devices/release", s.authed(s.handleRelease))
	mux.HandleFunc("POST /api/devices/revoke", s.authed(s.handleRevoke))
	mux.HandleFunc("POST /api/policies", s.authed(s.handleCreatePolicy))
	mux.HandleFunc("POST /api/policies/assign", s.authed(s.handleAssignPolicy))
	// Kural editörü: politikaya kural ekle / kuralları listele (Go 1.22 {id}).
	mux.HandleFunc("POST /api/policies/{id}/rules", s.authed(s.handleAddRule))
	mux.HandleFunc("GET /api/policies/{id}/rules", s.authed(s.handleListRules))
	// Okuma (görünürlük) uçları — herhangi bir kimlik doğrulanmış admin (VIEWER+).
	mux.HandleFunc("GET /api/devices", s.authed(s.handleListDevices))
	mux.HandleFunc("GET /api/devices/{id}", s.authed(s.handleDeviceDetail))
	mux.HandleFunc("GET /api/events", s.authed(s.handleListEvents))
	mux.HandleFunc("GET /api/summary", s.authed(s.handleSummary))
	mux.HandleFunc("GET /api/audit", s.authed(s.handleListAudit))
	return securityHeaders(mux)
}

// securityHeaders, tüm yanıtlara temel sertleştirme başlıkları ekler:
// MIME-sniffing kapalı, clickjacking (iframe) reddi, referrer sızıntısı yok.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// authed, Bearer oturum token'ını doğrulayıp adminID'yi handler'a geçirir.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		id, ok := s.sessions.Verify(tok, s.now())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "yetkisiz")
			return
		}
		h(w, r, id)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	adminID, hash, err := s.auth.LookupAdmin(r.Context(), req.Email)
	if err != nil || adminID == "" {
		writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
		return
	}
	ok, err := security.VerifyPassword(hash, req.Password)
	if err != nil || !ok {
		writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
		return
	}
	token := s.sessions.Sign(adminID, s.now().Add(s.ttl))
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request, adminID string) {
	token, err := s.adminSvc.IssueEnrollmentToken(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"enrollment_token": token})
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.QuarantineDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "quarantine_queued"})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.ReleaseDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "release_queued"})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.RevokeDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := s.adminSvc.CreatePolicy(r.Context(), adminID, req.Name, req.Version)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"policy_id": id})
}

func (s *Server) handleAssignPolicy(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
		PolicyID string `json:"policy_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.AssignPolicy(r.Context(), adminID, req.DeviceID, req.PolicyID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request, adminID string) {
	policyID := r.PathValue("id")
	var req struct {
		Type       string  `json:"type"`
		Target     string  `json:"target"`
		Start      string  `json:"start"`
		End        string  `json:"end"`
		ActiveDays []int32 `json:"active_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	in := admin.RuleInput{
		Type: req.Type, Target: req.Target, Start: req.Start, End: req.End, ActiveDays: req.ActiveDays,
	}
	if respondErr(w, s.adminSvc.AddPolicyRule(r.Context(), adminID, policyID, in)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rule_added"})
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request, adminID string) {
	rules, err := s.adminSvc.ListPolicyRules(r.Context(), adminID, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, _ string) {
	devices, err := s.reader.Devices(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request, _ string) {
	detail, ok, err := s.reader.DeviceDetail(r.Context(), r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "cihaz bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_detail": detail})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, _ string) {
	events, err := s.reader.Events(r.Context(), r.URL.Query().Get("device_id"), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request, _ string) {
	summary, err := s.reader.Summary(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary})
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, _ string) {
	audit, err := s.reader.Audit(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit})
}

// --- yardımcılar ---

func intParam(r *http.Request, name string) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "geçersiz JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// respondErr, admin servis hatasını uygun HTTP durumuna çevirir. Hata varsa
// yanıtı yazar ve true döner.
func respondErr(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, admin.ErrForbidden) {
		writeErr(w, http.StatusForbidden, "yetki yetersiz")
		return true
	}
	if errors.Is(err, admin.ErrInvalidRule) {
		writeErr(w, http.StatusBadRequest, "geçersiz kural")
		return true
	}
	writeErr(w, http.StatusInternalServerError, "işlem başarısız")
	return true
}
