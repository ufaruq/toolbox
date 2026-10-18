// Package connectors owns the credential-bearing executor. Connector plans are
// immutable and the executor only understands reviewed, fixed request shapes.
package connectors

import (
	"context"
	"errors"
	"time"
)

type AccessFunc = func(context.Context) (string, error)
type AuthorizeFunc = func(context.Context) error

type Metadata struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	MIMEType     string    `json:"mime_type"`
	ModifiedTime time.Time `json:"modified_time"`
}
type Result struct {
	FileID       string    `json:"file_id"`
	Text         string    `json:"text"`
	MIMEType     string    `json:"mime_type"`
	ModifiedTime time.Time `json:"modified_time"`
	RetrievedAt  time.Time `json:"retrieved_at"`
	Untrusted    bool      `json:"untrusted"`
}
type Manifest struct {
	ConnectorID, Version, Tool, Action, Description string
	RequiredScopes                                  []string
	MaxBytes                                        int
	ReadOnly                                        bool
	InputSchema                                     string
}

var (
	ErrInvalidInput = errors.New("INVALID_TOOL_ARGUMENTS")
	ErrUnsupported  = errors.New("UNSUPPORTED_RESOURCE")
	ErrRestricted   = errors.New("DOCUMENT_DOWNLOAD_RESTRICTED")
	ErrTooLarge     = errors.New("DOCUMENT_TOO_LARGE")
	ErrProvider     = errors.New("PROVIDER_UNAVAILABLE")
	ErrReauth       = errors.New("REAUTHENTICATION_REQUIRED")
)
