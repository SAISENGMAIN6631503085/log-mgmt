package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"logmgmt/ingest/normalize"
)

// Endpoint tests with in-memory stand-ins for Postgres (keys) and ClickHouse (store). The same
// endpoints are also tested end to end against the real databases by the pytest suite
// (tests/test_ingest_api.py, test_dedup.py, test_assignment_samples.py).

const secret = "test-secret-that-is-at-least-32-characters"

type fakeKeys map[string]string

func (k fakeKeys) TenantForKey(_ context.Context, key string) (string, error) { return k[key], nil }

type fakeStore struct {
	events []*normalize.Event
	down   bool
}

func (f *fakeStore) Insert(_ context.Context, evs []*normalize.Event) (int, error) {
	if f.down {
		return 0, errors.New("connection refused")
	}
	f.events = append(f.events, evs...)
	return len(evs), nil
}

func (f *fakeStore) count(tenant, source string) int {
	n := 0
	for _, e := range f.events {
		if e.Tenant == tenant && (source == "" || e.Source == source) {
			n++
		}
	}
	return n
}

type fakeGeo map[string]string

func (g fakeGeo) Country(ip string) string { return g[ip] }

func newServer(store *fakeStore) *Server {
	routes, _ := normalize.ParseTenantMap("10.1.0.0/16=tA,10.2.0.0/16=tB")
	return &Server{
		Config: Config{JWTSecret: secret, SyslogToken: "secret", TenantRoutes: routes,
			DefaultTenant: "tDefault", RetentionDays: 7},
		Store: store,
		Keys:  fakeKeys{"keyA": "tA", "keyB": "tB"},
		GeoIP: fakeGeo{"1.46.10.5": "TH"},
		Now:   time.Now,
	}
}

func call(t *testing.T, srv *Server, req *http.Request) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func jsonReq(path, key string, body any) *http.Request {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	return r
}

func fileReq(path, filename, source, content string) *http.Request {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", source)
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, path, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func bearer(role, tenant string) string {
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "x", "role": role, "tenant": tenant, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	return "Bearer " + tok
}

func nowISO(d time.Duration) string { return time.Now().UTC().Add(d).Format(time.RFC3339) }

func num(v any) int {
	f, _ := v.(float64)
	return int(f)
}

// --- JSON ingest (from tests/test_ingest_api.py) ---

func TestSingleEvent(t *testing.T) {
	st := &fakeStore{}
	code, body := call(t, newServer(st), jsonReq("/api/ingest", "keyA",
		map[string]any{"timestamp": nowISO(0), "event_type": "login_failed", "ip": "203.0.113.7"}))
	if code != 200 || num(body["accepted"]) != 1 || st.count("tA", "api") != 1 {
		t.Errorf("%d %v", code, body)
	}
}

func TestAssignmentPathIngestIsTheSameEndpoint(t *testing.T) {
	st := &fakeStore{}
	code, _ := call(t, newServer(st), jsonReq("/ingest", "keyA", map[string]any{"timestamp": nowISO(0)}))
	if code != 200 || st.count("tA", "") != 1 {
		t.Errorf("POST /ingest: %d", code)
	}
}

func TestTenantComesFromKeyNotBody(t *testing.T) {
	st := &fakeStore{}
	_, body := call(t, newServer(st), jsonReq("/api/ingest", "keyA", map[string]any{"timestamp": nowISO(0), "tenant": "tB"}))
	rejected, _ := body["rejected"].([]any)
	if num(body["accepted"]) != 0 || num(body["rejected_count"]) != 1 || len(rejected) != 1 ||
		!strings.Contains(fmt.Sprint(rejected[0].(map[string]any)["error"]), "use that tenant's key") {
		t.Errorf("%v", body)
	}
	if len(st.events) != 0 {
		t.Error("nothing may be stored")
	}
}

func TestMatchingTenantInBodyIsAccepted(t *testing.T) {
	st := &fakeStore{}
	_, body := call(t, newServer(st), jsonReq("/api/ingest", "keyA", map[string]any{"timestamp": nowISO(0), "tenant": "tA"}))
	if num(body["accepted"]) != 1 || st.count("tA", "") != 1 {
		t.Errorf("%v", body)
	}
}

func TestMissingOrWrongKeyIs401(t *testing.T) {
	for _, key := range []string{"", "lm_wrong"} {
		st := &fakeStore{}
		code, _ := call(t, newServer(st), jsonReq("/api/ingest", key, map[string]any{"timestamp": nowISO(0)}))
		if code != 401 || len(st.events) != 0 {
			t.Errorf("key %q: %d", key, code)
		}
	}
}

func TestBatchPartialSuccess(t *testing.T) {
	st := &fakeStore{}
	batch := []any{
		map[string]any{"timestamp": nowISO(0), "event_type": "ok"},
		map[string]any{"timestamp": "not a date"},
		map[string]any{"timestamp": nowISO(-30 * 24 * time.Hour)}, // outside retention: stored at receipt time, tagged
		map[string]any{"timestamp": nowISO(0), "severity": 3},
	}
	_, body := call(t, newServer(st), jsonReq("/api/ingest", "keyA", batch))
	rejected, _ := body["rejected"].([]any)
	if num(body["accepted"]) != 3 || num(body["rejected_count"]) != 1 || num(body["time_adjusted"]) != 1 ||
		len(rejected) != 1 || num(rejected[0].(map[string]any)["index"]) != 1 || st.count("tA", "") != 3 {
		t.Errorf("%v", body)
	}
}

func TestOtherJSONSourceViaQuery(t *testing.T) {
	st := &fakeStore{}
	rec := func(user string) map[string]any {
		return map[string]any{"eventTime": nowISO(0), "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
			"responseElements": map[string]any{"ConsoleLogin": "Failure"}, "sourceIPAddress": "203.0.113.9",
			"userIdentity": map[string]any{"userName": user}}
	}
	_, body := call(t, newServer(st), jsonReq("/api/ingest?source=aws", "keyA",
		map[string]any{"Records": []any{rec("carol"), rec("dave")}}))
	if num(body["accepted"]) != 2 || st.count("tA", "aws") != 2 {
		t.Errorf("%v", body)
	}
}

func TestCloudTrailFileIsRecognisedWithoutSource(t *testing.T) {
	st := &fakeStore{}
	_, body := call(t, newServer(st), jsonReq("/api/ingest", "keyA", map[string]any{"Records": []any{
		map[string]any{"eventTime": nowISO(0), "eventName": "RunInstances"}}}))
	if num(body["accepted"]) != 1 || st.count("tA", "aws") != 1 {
		t.Errorf("%v", body)
	}
}

func TestUnknownSourceIs400(t *testing.T) {
	code, _ := call(t, newServer(&fakeStore{}), jsonReq("/api/ingest?source=nope", "keyA", map[string]any{}))
	if code != 400 {
		t.Errorf("got %d", code)
	}
}

func TestTooManyEventsIs413(t *testing.T) {
	srv := newServer(&fakeStore{})
	srv.Config.MaxEventsPerBatch = 2
	batch := []any{map[string]any{"timestamp": nowISO(0)}, map[string]any{"timestamp": nowISO(0)}, map[string]any{"timestamp": nowISO(0)}}
	if code, _ := call(t, srv, jsonReq("/api/ingest", "keyA", batch)); code != 413 {
		t.Errorf("got %d", code)
	}
}

func TestStoreDownIs503AndNothingStored(t *testing.T) {
	code, body := call(t, newServer(&fakeStore{down: true}), jsonReq("/api/ingest", "keyA", map[string]any{"timestamp": nowISO(0)}))
	if code != 503 || !strings.Contains(fmt.Sprint(body["detail"]), "retry later") {
		t.Errorf("%d %v", code, body)
	}
}

func TestCountryIsAddedAtIngest(t *testing.T) {
	st := &fakeStore{}
	call(t, newServer(st), jsonReq("/api/ingest", "keyA", []any{
		map[string]any{"timestamp": nowISO(0), "ip": "1.46.10.5", "user": "a"},
		map[string]any{"timestamp": nowISO(0), "ip": "10.0.1.10", "user": "b"}}))
	if len(st.events) != 2 || st.events[0].SrcCountry == nil || *st.events[0].SrcCountry != "TH" || st.events[1].SrcCountry != nil {
		t.Errorf("countries: %+v", st.events)
	}
}

// --- file upload ---

func adCSV() string {
	return fmt.Sprintf("TimeCreated,EventID,Computer,TargetUserName,IpAddress,IpPort\n%s,4625,DC01,bob,203.0.113.5,5000\n", nowISO(0))
}

func TestFileUploadCSV(t *testing.T) {
	st := &fakeStore{}
	csv := adCSV() + nowISO(0) + ",4624,DC01,bob,-,-\n"
	r := fileReq("/api/ingest/file", "sec.csv", "ad", csv)
	r.Header.Set("X-API-Key", "keyA")
	_, body := call(t, newServer(st), r)
	if num(body["accepted"]) != 2 || st.count("tA", "ad") != 2 {
		t.Errorf("%v", body)
	}
}

func TestFileUploadUnparseableIs400(t *testing.T) {
	r := fileReq("/api/ingest/file", "x.json", "aws", "not json")
	r.Header.Set("X-API-Key", "keyA")
	if code, _ := call(t, newServer(&fakeStore{}), r); code != 400 {
		t.Errorf("got %d", code)
	}
}

func TestFileUploadNeedsKey(t *testing.T) {
	if code, _ := call(t, newServer(&fakeStore{}), fileReq("/api/ingest/file", "x.csv", "ad", "a\n1\n")); code != 401 {
		t.Errorf("got %d", code)
	}
}

func TestUIUploadGoesToTheViewedTenant(t *testing.T) {
	// The website's upload: the admin's login token, tenant from ?tenant= (not an API key).
	st := &fakeStore{}
	r := fileReq("/api/ingest/upload?tenant=tB", "sec.csv", "ad", adCSV())
	r.Header.Set("Authorization", bearer("admin", "tA"))
	code, body := call(t, newServer(st), r)
	if code != 200 || num(body["accepted"]) != 1 || st.count("tB", "ad") != 1 || st.count("tA", "") != 0 {
		t.Errorf("%d %v", code, body)
	}
}

func TestUIUploadIsAdminOnly(t *testing.T) {
	st := &fakeStore{}
	r := fileReq("/api/ingest/upload", "sec.csv", "ad", adCSV())
	r.Header.Set("Authorization", bearer("viewer", "tA"))
	if code, _ := call(t, newServer(st), r); code != 403 || len(st.events) != 0 {
		t.Errorf("got %d", code)
	}
}

func TestUIUploadNeedsLogin(t *testing.T) {
	if code, _ := call(t, newServer(&fakeStore{}), fileReq("/api/ingest/upload", "sec.csv", "ad", adCSV())); code != 401 {
		t.Errorf("got %d", code)
	}
}

func TestUIUploadRejectsTokenSignedWithAnotherSecret(t *testing.T) {
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "x", "role": "admin", "tenant": "tA", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("some-other-secret-that-is-32-chars-long"))
	r := fileReq("/api/ingest/upload", "sec.csv", "ad", adCSV())
	r.Header.Set("Authorization", "Bearer "+tok)
	if code, _ := call(t, newServer(&fakeStore{}), r); code != 401 {
		t.Errorf("got %d", code)
	}
}

// --- syslog (internal, from Vector) ---

func syslogLine(text string) string {
	return fmt.Sprintf("<132>%s %s", time.Now().UTC().Format("Jan _2 15:04:05"), text)
}

func syslogReq(token string, recs []map[string]string) *http.Request {
	r := jsonReq("/api/ingest/syslog", "", recs)
	if token != "" {
		r.Header.Set("X-Ingest-Token", token)
	}
	return r
}

func TestSyslogRequiresToken(t *testing.T) {
	recs := []map[string]string{{"message": syslogLine("fw action=deny src=1.2.3.4"), "host": "10.0.0.1"}}
	for _, tok := range []string{"", "wrong"} {
		if code, _ := call(t, newServer(&fakeStore{}), syslogReq(tok, recs)); code != 401 {
			t.Errorf("token %q: got %d", tok, code)
		}
	}
}

func TestSyslogRefusedWhenNoTokenConfigured(t *testing.T) {
	// Fail closed: an empty token in config must not mean "no auth".
	srv := newServer(&fakeStore{})
	srv.Config.SyslogToken = ""
	r := jsonReq("/api/ingest/syslog", "", []any{})
	r.Header.Set("X-Ingest-Token", "")
	if code, _ := call(t, srv, r); code != 401 {
		t.Errorf("got %d", code)
	}
}

func TestSyslogTenantBySenderAndClassification(t *testing.T) {
	st := &fakeStore{}
	_, body := call(t, newServer(st), syslogReq("secret", []map[string]string{
		{"message": syslogLine("fw01 action=deny src=203.0.113.4 dst=10.1.0.5") + "\n", "host": "10.1.0.9"},
		{"message": syslogLine("sw01 %LINK-3-UPDOWN: event_type=link_down"), "host": "10.2.3.4"},
	}))
	if num(body["accepted"]) != 2 || st.count("tA", "firewall") != 1 || st.count("tB", "network") != 1 {
		t.Errorf("%v", body)
	}
}

func TestSyslogUnknownSenderGoesToDefaultTenant(t *testing.T) {
	st := &fakeStore{}
	call(t, newServer(st), syslogReq("secret", []map[string]string{{"message": syslogLine("fw01 action=deny src=203.0.113.4"), "host": "192.0.2.1"}}))
	if st.count("tDefault", "") != 1 {
		t.Errorf("events: %+v", st.events)
	}
}
