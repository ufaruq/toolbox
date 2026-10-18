package oauth

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

// ErrAccountLinking deliberately discloses neither the expected mailbox nor
// resolver failures. Rejected issued credentials remain cleanup-only.
var ErrAccountLinking = errors.New("CORPORATE_ACCOUNT_LINK_DENIED")

// CorporateIdentity is an explicit, trusted mapping to a permitted Google
// Workspace mailbox. Email is an authorization attribute, never an account key.
// Both values must be canonical ASCII; the mailbox domain must equal HostedDomain.
// Local parts are compared exactly without case, dot, plus, or alias folding.
type CorporateIdentity struct {
	Email, HostedDomain string
}

// TrustedOwnerIdentityResolver resolves a previously authenticated Toolbox owner
// ID from a trusted IdP integration or reviewed server configuration. Implementers
// must verify their source and its binding to the owner. Never derive this value
// from request JSON, query parameters, email headers, login_hint, or Google claims.
// Resolution must honor context cancellation. An unmapped owner must return an
// error; every resolution failure denies activation.
type TrustedOwnerIdentityResolver interface {
	ResolveCorporateIdentity(context.Context, string) (CorporateIdentity, error)
}

// NewCorporateService opts into exact-person Workspace linking. The provider must
// explicitly advertise the openid+email+drive.file scope contract. The fixture
// deliberately cannot satisfy this production identity mode.
func NewCorporateService(repo domain.Repository, secrets SecretStore, provider Provider, resolver TrustedOwnerIdentityResolver) (*Service, error) {
	if resolver == nil {
		return nil, ErrConfiguration
	}
	service, err := newService(repo, secrets, provider)
	if err != nil {
		return nil, err
	}
	if !sameScopes(service.scopes, corporateScopes()) {
		return nil, ErrConfiguration
	}
	service.ownerIdentity = resolver
	return service, nil
}

func corporateScopes() []string { return []string{"openid", "email", domain.DriveScope} }

func (s *Service) authorizeCorporateLink(ctx context.Context, ownerID string, identity VerifiedIdentity) error {
	if s.ownerIdentity == nil {
		return nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	expected, err := s.ownerIdentity.ResolveCorporateIdentity(resolveCtx, ownerID)
	actual := CorporateIdentity{Email: identity.Email, HostedDomain: identity.HostedDomain}
	if err != nil || resolveCtx.Err() != nil || identity.Issuer != "https://accounts.google.com" || !identity.EmailVerified || !validCorporateIdentity(expected) || !validCorporateIdentity(actual) || expected != actual {
		return ErrAccountLinking
	}
	return nil
}

func validCorporateIdentity(identity CorporateIdentity) bool {
	domain := identity.HostedDomain
	if len(identity.Email) > 254 || !validHostedDomain(domain) || strings.Count(identity.Email, "@") != 1 {
		return false
	}
	local, emailDomain, _ := strings.Cut(identity.Email, "@")
	if emailDomain != domain || local == "" || strings.ContainsAny(local, "\"\\()<>[]:; \t\r\n") {
		return false
	}
	for _, r := range local {
		if r < 33 || r > 126 {
			return false
		}
	}
	parsed, err := mail.ParseAddress(identity.Email)
	return err == nil && parsed.Address == identity.Email && parsed.Name == ""
}

func validHostedDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
