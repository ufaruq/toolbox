package domain

import "time"

// CallerCandidate records a verified identity awaiting an owner's decision.
// It carries no credentials or permissions; approval requires a CallerProfile.
type CallerCandidate struct {
	ID, OwnerID, Issuer, UserID, ClientID, Status string
	FirstSeenAt, DecidedAt                        time.Time
}
