// Package server is the ingest HTTP API: JSON, file upload and syslog (from Vector).
// It normalizes every log, adds the country of the source IP and stores the batch in ClickHouse.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"logmgmt/ingest/geoip"
	"logmgmt/ingest/normalize"
)

const (
	MaxUploadBytes     = 50 << 20 // 50 MB (Caddy allows 55 MB for the multipart overhead)
	maxErrorsReturned  = 100      // keep responses small when a whole file is bad
	timeAdjustedTag    = "time_adjusted"
	defaultMaxPerBatch = 10_000
)

// Store saves normalized events and says how many were new (the rest were duplicates).
type Store interface {
	Insert(ctx context.Context, events []*normalize.Event) (int, error)
}

type Config struct {
	JWTSecret         string
	SyslogToken       string
	TenantRoutes      []normalize.TenantRoute
	DefaultTenant     string
	RetentionDays     int
	MaxEventsPerBatch int
}

type Server struct {
	Config Config
	Store  Store
	Keys   Keys
	GeoIP  geoip.Lookup
	Now    func() time.Time // the clock, replaceable in tests
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", s.ingestJSON)
	mux.HandleFunc("POST /ingest", s.ingestJSON) // the assignment's name for the same endpoint
	mux.HandleFunc("POST /api/ingest/file", s.ingestFile)
	mux.HandleFunc("POST /api/ingest/upload", s.ingestUpload)
	mux.HandleFunc("POST /api/ingest/syslog", s.ingestSyslog)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

// --- responses -------------------------------------------------------------------------

type httpError struct {
	status int
	detail string
}

type Rejected struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// Result is the same shape the backend returned before ingestion moved to Go.
type Result struct {
	Accepted      int        `json:"accepted"`
	TimeAdjusted  int        `json:"time_adjusted"` // stored at receipt time: own time out of range
	Duplicates    int        `json:"duplicates"`    // valid but already stored (e.g. a re-uploaded file)
	RejectedCount int        `json:"rejected_count"`
	Rejected      []Rejected `json:"rejected"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail answers with {"detail": "..."}, the error shape the website already understands.
func fail(w http.ResponseWriter, e *httpError) {
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	writeJSON(w, e.status, map[string]string{"detail": e.detail})
}

// --- the shared pipeline ---------------------------------------------------------------

type item struct {
	source  string
	payload any
	tenant  string
}

// process normalizes the items, stores the good ones and reports the bad ones.
//
// Partial success on purpose: one malformed line in a 10k-line file shouldn't block the other
// 9,999. The caller gets each rejected index and why.
//
// Times outside [now - RETENTION_DAYS, now + 1 day] are not rejected: the event is stored at the
// receipt time and tagged "time_adjusted"; its original time stays in raw. Old sample files and
// devices with a wrong clock are common, and dropping their events would hide real activity.
// Storing them at their real (old) time doesn't work either: retention would delete them.
func (s *Server) process(ctx context.Context, items []item) (*Result, *httpError) {
	if limit := s.maxPerBatch(); len(items) > limit {
		return nil, &httpError{http.StatusRequestEntityTooLarge,
			fmt.Sprintf("too many events: %d > %d; split the batch", len(items), limit)}
	}
	now := s.Now().UTC()
	res := &Result{Rejected: []Rejected{}}
	var events []*normalize.Event
	for i, it := range items {
		e, err := s.normalizeOne(it, now)
		if err != nil {
			res.RejectedCount++
			if len(res.Rejected) < maxErrorsReturned {
				res.Rejected = append(res.Rejected, Rejected{Index: i, Error: truncate(err.Error(), 300)})
			}
			continue
		}
		if CheckTSWindow(e.TS, s.Config.RetentionDays, now) != "" {
			e.TS = now
			e.Tags = append(e.Tags, timeAdjustedTag)
			res.TimeAdjusted++
		}
		events = append(events, e)
	}
	accepted, err := s.Store.Insert(ctx, events)
	if err != nil {
		// ClickHouse down or failing: nothing is stored, and the sender should retry later
		// (Vector does so by itself; duplicates are skipped, so a retry is safe).
		log.Printf("storing %d events failed: %v", len(events), err)
		return nil, &httpError{http.StatusServiceUnavailable, "event store unavailable; nothing was stored, retry later"}
	}
	res.Accepted = accepted
	res.Duplicates = len(events) - accepted
	return res, nil
}

func (s *Server) normalizeOne(it item, now time.Time) (*normalize.Event, error) {
	if !normalize.Known(it.source) {
		return nil, fmt.Errorf("unknown source %q; expected one of %v", it.source, normalize.Sources)
	}
	// A tenant written inside the event must match the API key's tenant. Rejecting (rather than
	// silently re-labelling) makes a wrong key or a cross-tenant write attempt visible.
	if d, ok := it.payload.(map[string]any); ok {
		if t := d["tenant"]; t != nil && t != "" && t != it.tenant {
			return nil, fmt.Errorf("event says tenant %q but this API key belongs to tenant %q; use that tenant's key",
				fmt.Sprint(t), it.tenant)
		}
	}
	e, err := normalize.Normalize(it.source, it.payload, it.tenant, now)
	if err != nil {
		return nil, err
	}
	if e.SrcIP != nil { // enrichment: the same for every source
		if c := s.GeoIP.Country(*e.SrcIP); c != "" {
			e.SrcCountry = &c
		}
	}
	return e, nil
}

func (s *Server) maxPerBatch() int {
	if s.Config.MaxEventsPerBatch > 0 {
		return s.Config.MaxEventsPerBatch
	}
	return defaultMaxPerBatch
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, items []item) {
	res, herr := s.process(r.Context(), items)
	if herr != nil {
		fail(w, herr)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func checkSource(source string) *httpError {
	if !normalize.Known(source) {
		return &httpError{http.StatusBadRequest, fmt.Sprintf("unknown source %q; expected one of %v", source, normalize.Sources)}
	}
	return nil
}

// --- endpoints -------------------------------------------------------------------------

// ingestJSON: one event, an array of events, or a CloudTrail Records file. ?source= picks the
// normalizer for all of them; without it each event's own "source" field is used, else "api".
func (s *Server) ingestJSON(w http.ResponseWriter, r *http.Request) {
	tenant, herr := s.tenantFromAPIKey(r)
	if herr != nil {
		fail(w, herr)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxUploadBytes))
	if err != nil {
		fail(w, &httpError{http.StatusRequestEntityTooLarge, "request body too large"})
		return
	}
	body, err := decodeJSON(data)
	if err != nil {
		fail(w, &httpError{http.StatusUnprocessableEntity, "body is not valid JSON: " + err.Error()})
		return
	}
	source := r.URL.Query().Get("source")
	if d, ok := body.(map[string]any); ok && source == "" {
		if _, isTrail := d["Records"]; isTrail {
			source = "aws" // a CloudTrail file is unambiguous even without ?source=
		}
	}
	if source != "" {
		if herr := checkSource(source); herr != nil {
			fail(w, herr)
			return
		}
	}
	payloads, err := SplitPayloads(source, body)
	if err != nil {
		fail(w, &httpError{http.StatusBadRequest, err.Error()})
		return
	}
	items := make([]item, len(payloads))
	for i, p := range payloads {
		src := source
		if src == "" {
			src = "api"
			if d, ok := p.(map[string]any); ok && d["source"] != nil && d["source"] != "" {
				src = strings.ToLower(fmt.Sprint(d["source"]))
			}
		}
		items[i] = item{src, p, tenant}
	}
	s.respond(w, r, items)
}

// ingestFile: a JSON / NDJSON / CSV / log file, authenticated by an API key.
func (s *Server) ingestFile(w http.ResponseWriter, r *http.Request) {
	tenant, herr := s.tenantFromAPIKey(r)
	if herr != nil {
		fail(w, herr)
		return
	}
	s.upload(w, r, tenant)
}

// ingestUpload: the same upload for the website's "Add logs" page, authenticated by the login
// token instead of an API key. Admin only: viewers are read-only.
func (s *Server) ingestUpload(w http.ResponseWriter, r *http.Request) {
	tenant, herr := s.adminTenant(r)
	if herr != nil {
		fail(w, herr)
		return
	}
	s.upload(w, r, tenant)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, tenant string) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes+1<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		fail(w, &httpError{http.StatusUnprocessableEntity, "expected a multipart form with `file` and `source`"})
		return
	}
	source := r.FormValue("source")
	if source == "" {
		fail(w, &httpError{http.StatusUnprocessableEntity, "missing form field `source`"})
		return
	}
	if herr := checkSource(source); herr != nil {
		fail(w, herr)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		fail(w, &httpError{http.StatusUnprocessableEntity, "missing form field `file`"})
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, MaxUploadBytes+1))
	if err != nil {
		fail(w, &httpError{http.StatusBadRequest, "could not read the file"})
		return
	}
	if len(content) > MaxUploadBytes {
		fail(w, &httpError{http.StatusRequestEntityTooLarge, fmt.Sprintf("file larger than %d MB", MaxUploadBytes>>20)})
		return
	}
	payloads, err := ParseUpload(header.Filename, content, source)
	if err != nil {
		fail(w, &httpError{http.StatusBadRequest, "could not parse file: " + truncate(err.Error(), 300)})
		return
	}
	items := make([]item, len(payloads))
	for i, p := range payloads {
		items[i] = item{source, p, tenant}
	}
	s.respond(w, r, items)
}

type syslogRecord struct {
	Message *string `json:"message"`
	Host    string  `json:"host"` // sender IP, added by Vector's socket source
}

// ingestSyslog is internal: only Vector calls it. Caddy refuses it from outside (see the
// Caddyfile); the token is a second lock in case the service is ever exposed directly.
func (s *Server) ingestSyslog(w http.ResponseWriter, r *http.Request) {
	got, want := r.Header.Get("X-Ingest-Token"), s.Config.SyslogToken
	// ConstantTimeCompare: the token can't be guessed byte by byte from response timings.
	// An empty configured token fails closed instead of meaning "no auth".
	if want == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		fail(w, &httpError{http.StatusUnauthorized, "invalid ingest token"})
		return
	}
	var records []syslogRecord
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxUploadBytes))
	if err := dec.Decode(&records); err != nil {
		fail(w, &httpError{http.StatusUnprocessableEntity, "expected a JSON array of {message, host}"})
		return
	}
	items := make([]item, 0, len(records))
	for _, rec := range records {
		if rec.Message == nil {
			fail(w, &httpError{http.StatusUnprocessableEntity, "every record needs a message"})
			return
		}
		line := strings.TrimSpace(*rec.Message)
		tenant := normalize.TenantForSender(rec.Host, s.Config.TenantRoutes, s.Config.DefaultTenant)
		items = append(items, item{ClassifySyslog(line), line, tenant})
	}
	s.respond(w, r, items)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ErrWeakSecret is returned at startup for a missing or example JWT secret.
var ErrWeakSecret = errors.New("JWT_SECRET must be set to a random string of at least 32 chars (e.g. `openssl rand -hex 32`)")
