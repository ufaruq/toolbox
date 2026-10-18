package app

import (
	"context"
	"errors"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/server"
)

var errProviderUnavailable = errors.New("PROVIDER_UNAVAILABLE")

// UnavailableIntegration is the hosted provider boundary until live Google
// wiring is available. It never substitutes a synthetic provider or content.
type UnavailableIntegration struct{}

func (UnavailableIntegration) Available() bool { return false }
func (UnavailableIntegration) Start(context.Context, string, string) (string, error) {
	return "", errProviderUnavailable
}
func (UnavailableIntegration) Complete(context.Context, string, string, string, string) (domain.Connection, error) {
	return domain.Connection{}, errProviderUnavailable
}
func (UnavailableIntegration) Inspect(context.Context, string, string, func(context.Context) error) (server.Document, error) {
	return server.Document{}, errProviderUnavailable
}
func (UnavailableIntegration) Read(context.Context, string, string, func(context.Context) error) (server.Document, error) {
	return server.Document{}, errProviderUnavailable
}
func (UnavailableIntegration) Cleanup(context.Context, string, int64) error {
	return errProviderUnavailable
}
func (UnavailableIntegration) FixtureAuthorize(context.Context, string) (string, error) {
	return "", domain.ErrDenied
}

var _ server.Integration = UnavailableIntegration{}
