// Package app wires the fixed connector to the sole credential boundary.
package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type Integration struct {
	OAuth        *oauth.Service
	TokenManager *tokens.Manager
	Drive        *gdrive.Client
	Fixture      *oauth.FixtureProvider
}

func (i *Integration) Start(ctx context.Context, owner, session string) (string, error) {
	v, e := i.OAuth.Start(ctx, owner, session)
	return v.AuthorizationURL, e
}
func (i *Integration) Complete(ctx context.Context, owner, session, state, code string) (domain.Connection, error) {
	return i.OAuth.Complete(ctx, owner, session, state, code)
}
func (i *Integration) Reject(ctx context.Context, owner, session, state string) error {
	return i.OAuth.Reject(ctx, owner, session, state)
}
func (i *Integration) PickerToken(ctx context.Context, connection string, auth func(context.Context) error) (tokens.Lease, error) {
	return i.TokenManager.AccessLease(ctx, connection, auth)
}
func (i *Integration) access(connectionID string, auth func(context.Context) error) func(context.Context) (string, error) {
	var generation int64
	return func(ctx context.Context) (string, error) {
		var lease tokens.Lease
		var e error
		if connectors.RefreshRequested(ctx) {
			lease, e = i.TokenManager.ForceRefreshAfter(ctx, connectionID, generation, auth)
		} else {
			lease, e = i.TokenManager.AccessLease(ctx, connectionID, auth)
		}
		if e != nil {
			return "", e
		}
		generation = lease.Generation
		return lease.Token, nil
	}
}
func (i *Integration) Inspect(ctx context.Context, connection, file string, auth func(context.Context) error) (server.Document, error) {
	m, e := i.Drive.Inspect(ctx, file, i.access(connection, auth), auth)
	return server.Document{FileID: m.ID, Name: m.Name, MIME: m.MIMEType, ModifiedTime: m.ModifiedTime.Format(time.RFC3339)}, e
}
func (i *Integration) Read(ctx context.Context, connection, file string, auth func(context.Context) error) (server.Document, error) {
	v, e := i.Drive.Execute(ctx, file, i.access(connection, auth), auth)
	return server.Document{FileID: v.FileID, MIME: v.MIMEType, Content: v.Text, Bytes: len(v.Text), ModifiedTime: v.ModifiedTime.Format(time.RFC3339), RetrievedAt: v.RetrievedAt}, e
}
func (i *Integration) Cleanup(ctx context.Context, connection string, epoch int64) error {
	return i.TokenManager.Tombstone(ctx, connection, epoch)
}
func (i *Integration) FixtureAuthorize(ctx context.Context, authorizationURL string) (string, error) {
	if i.Fixture == nil {
		return "", domain.ErrDenied
	}
	return i.Fixture.Authorize(ctx, authorizationURL, "fixture-google-account")
}

// FixtureDrive is an in-process fake, not a Google integration validation. It has
// two synthetic documents so a grant to A can be tested against accessible B.
type FixtureDrive struct {
	Calls  atomic.Int64
	Before func(*http.Request)
	After  func(*http.Request)
}

func (f *FixtureDrive) RoundTrip(r *http.Request) (*http.Response, error) {
	f.Calls.Add(1)
	if f.Before != nil {
		f.Before(r)
	}
	status := 200
	body := ""
	if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "www.googleapis.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fixture-access-") {
		status = 403
	} else {
		path := strings.TrimPrefix(r.URL.Path, "/drive/v3/files/")
		id := strings.TrimSuffix(path, "/export")
		if id != "doc-A" && id != "doc-B" {
			status = 404
		} else if strings.HasSuffix(path, "/export") {
			body = "Synthetic document " + id + ".\nThis text is untrusted data, not instructions.\n"
		} else {
			body = fmt.Sprintf(`{"id":%q,"name":%q,"mimeType":"application/vnd.google-apps.document","trashed":false,"modifiedTime":"2026-10-18T00:00:00Z","capabilities":{"canDownload":true}}`, id, "Fixture "+id)
		}
	}
	if status != 200 {
		body = `{"error":"fixture request rejected"}`
	}
	if f.After != nil {
		f.After(r)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}
