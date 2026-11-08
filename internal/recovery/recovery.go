// Package recovery fences authority after restoring a snapshot whose later
// revocations cannot be proved. It never dispatches or deletes provider material.
package recovery

import (
	"context"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
	"math"
	"time"
)

type Report struct{ Sessions, Credentials, Grants, Connections, Callers, OwnerLogins, Requests int }

func Invalidate(ctx context.Context, repo domain.Repository) (r Report, err error) {
	err = repo.Transact(ctx, func(st *domain.State) error {
		for id, p := range st.CallerProfiles {
			if p.Status == "active" {
				p.Status = "disabled"
				st.CallerProfiles[id] = p
				a := st.Agents[p.AgentID]
				a.Status = "disabled"
				st.Agents[p.AgentID] = a
				r.Callers++
			}
		}
		for id, login := range st.OwnerLogins {
			if login.Status == "pending" || login.Status == "exchanging" {
				login.Status = "cancelled"
				st.OwnerLogins[id] = login
				r.OwnerLogins++
			}
		}
		for id, request := range st.Requests {
			if request.Status == "pending" {
				request.Status = "cancelled"
				st.Requests[id] = request
				r.Requests++
			}
		}
		for id, s := range st.Sessions {
			if s.ExpiresAt.After(st.Now) {
				s.ExpiresAt = st.Now.Add(-time.Second)
				st.Sessions[id] = s
				r.Sessions++
			}
		}
		for id, c := range st.Credentials {
			if c.Status != "revoked" {
				c.Status = "revoked"
				st.Credentials[id] = c
				r.Credentials++
			}
		}
		for id, g := range st.Grants {
			if g.RevokedAt == nil {
				now := st.Now
				g.RevokedAt = &now
				st.Grants[id] = g
				r.Grants++
			}
		}
		for id, o := range st.OAuth {
			o.Consumed = true
			st.OAuth[id] = o
		}
		for id, c := range st.Connections {
			if c.Status == "disconnected" || c.Status == "disconnecting" {
				continue
			}
			if c.Epoch == math.MaxInt64 {
				return domain.ErrDenied
			}
			c.Epoch++
			c.Status = "disconnecting"
			st.Connections[id] = c
			r.Connections++
			j := domain.Cleanup{ID: security.ID(), ConnectionID: id, OwnerID: c.OwnerID, Epoch: c.Epoch, Status: "pending", CreatedAt: st.Now}
			st.Cleanup[j.ID] = j
		}
		if r.Sessions+r.Credentials+r.Grants+r.Connections+r.Callers+r.OwnerLogins+r.Requests > 0 {
			st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "service", ActorID: "recovery", Action: "recovery.authority_invalidated", Outcome: "blocked_pending_reconciliation"})
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	return r, nil
}
