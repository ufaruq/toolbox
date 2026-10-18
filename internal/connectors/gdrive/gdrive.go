// Package gdrive registers the reviewed Google Drive read-document tool. Plans
// contain only a validated exact file ID; all provider dispatch lives in the
// central connector executor.
package gdrive

import (
	"context"
	"net/http"

	"github.com/ufaruq/toolbox/internal/connectors"
	"github.com/ufaruq/toolbox/internal/domain"
)

type Client struct{ executor *connectors.Executor }

func New() *Client { return &Client{executor: connectors.NewExecutor()} }

// NewFixture is for hermetic tests and explicit local demo mode only.
func NewFixture(transport http.RoundTripper) *Client {
	return &Client{executor: connectors.NewFixtureExecutor(transport)}
}
func Manifest() connectors.Manifest {
	return connectors.Manifest{ConnectorID: "google_drive", Version: "1", Tool: domain.Tool, Action: domain.Action, Description: "Read the current plain-text export of exactly one selected Google document.", RequiredScopes: []string{domain.DriveScope}, MaxBytes: domain.MaxBytes, ReadOnly: true, InputSchema: `{"type":"object","additionalProperties":false,"required":["file_id"],"properties":{"file_id":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,256}$","minLength":1,"maxLength":256}}}`}
}
func (c *Client) Execute(ctx context.Context, fileID string, access func(context.Context) (string, error), authorize func(context.Context) error) (connectors.Result, error) {
	p, e := connectors.NewDriveReadPlan(fileID)
	if e != nil {
		return connectors.Result{}, e
	}
	return c.executor.Execute(ctx, p, access, authorize)
}
func (c *Client) Inspect(ctx context.Context, fileID string, access func(context.Context) (string, error), authorize func(context.Context) error) (connectors.Metadata, error) {
	p, e := connectors.NewDriveReadPlan(fileID)
	if e != nil {
		return connectors.Metadata{}, e
	}
	return c.executor.Inspect(ctx, p, access, authorize)
}
