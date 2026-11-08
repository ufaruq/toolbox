package store

import (
	"fmt"
	"github.com/ufaruq/toolbox/internal/domain"
	"testing"
	"time"
)

func BenchmarkReviewCallerValidation(b *testing.B) {
	for _, alias := range []bool{false, true} {
		for _, n := range []int{100, 1000, 5000} {
			b.Run(fmt.Sprintf("alias=%t/n=%d", alias, n), func(b *testing.B) {
				s := domain.NewState()
				now := time.Now()
				for i := 0; i < n; i++ {
					id := fmt.Sprintf("u%d", i)
					issuer, subject := "https://okta.example", id
					s.Users[id] = domain.User{ID: id, Issuer: issuer, Subject: subject, Status: "active"}
					if alias {
						issuer = "https://broker.example/realms/toolbox"
						s.IdentityAliases[domain.IdentityKey(issuer, subject)] = domain.IdentityAlias{Issuer: issuer, Subject: subject, OwnerID: id}
					}
					s.Agents[id] = domain.Agent{ID: id, OwnerID: id, Status: "active"}
					s.CallerProfiles[id] = domain.CallerProfile{ID: id, OwnerID: id, AgentID: id, Issuer: issuer, UserID: subject, ClientID: "client", Status: "active", ApprovedAt: now, ExpiresAt: now.Add(time.Hour)}
				}
				old := domain.NewState()
				if err := validate(old, s); err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for b.Loop() {
					if err := validate(old, s); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
