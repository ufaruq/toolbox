package store

import (
	"context"
	"errors"
	"github.com/ufaruq/toolbox/internal/domain"
	"testing"
	"time"
)

func seedGitHub(t *testing.T, r domain.Repository) {
	t.Helper()
	seed(t, r)
	if e := r.Transact(context.Background(), func(s *domain.State) error {
		c := domain.GitHubConnection{ID: "ghc", OwnerID: "u1", InstallationID: 42, RepositoryID: 99, RepositoryOwner: "org", RepositoryName: "repo", Epoch: 1, Status: "active"}
		s.GitHubConnections[c.ID] = c
		scope := domain.GitHubScope{Actions: []string{"files.read"}, Branches: []string{"main"}, Paths: []string{"src/"}}
		g := domain.GitHubGrant{ID: "ghg", OwnerID: "u1", AgentID: "a1", ConnectionID: c.ID, RepositoryID: 99, Epoch: 1, Scope: scope, NotBefore: s.Now, ExpiresAt: s.Now.Add(time.Hour)}
		s.GitHubGrants[g.ID] = g
		q := domain.GitHubRequest{ID: "ghq", OwnerID: "u1", AgentID: "a1", ConnectionID: c.ID, RepositoryID: 99, Epoch: 1, Scope: scope, Status: "approved", Digest: "digest", GrantID: g.ID, ExpiresAt: s.Now.Add(time.Hour), ReviewExpiresAt: s.Now.Add(time.Minute)}
		s.GitHubRequests[q.ID] = q
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestGitHubRepositoryInvariants(t *testing.T) { exerciseGitHubRepository(t, NewMemory()) }
func exerciseGitHubRepository(t *testing.T, r domain.Repository) {
	t.Helper()
	seedGitHub(t, r)
	for name, mutate := range map[string]func(*domain.State){
		"grant owner": func(s *domain.State) {
			g := s.GitHubGrants["ghg"]
			g.ID = "bad"
			g.AgentID = "a2"
			s.GitHubGrants[g.ID] = g
		},
		"wrong repository": func(s *domain.State) {
			g := s.GitHubGrants["ghg"]
			g.ID = "bad"
			g.RepositoryID = 100
			s.GitHubGrants[g.ID] = g
		},
		"widen actions": func(s *domain.State) {
			g := s.GitHubGrants["ghg"]
			g.Scope.Actions = append(g.Scope.Actions, "files.write")
			s.GitHubGrants[g.ID] = g
		},
		"delete grant": func(s *domain.State) { delete(s.GitHubGrants, "ghg") },
		"rebind connection": func(s *domain.State) {
			c := s.GitHubConnections["ghc"]
			c.InstallationID = 77
			s.GitHubConnections[c.ID] = c
		},
		"request rebind": func(s *domain.State) {
			q := s.GitHubRequests["ghq"]
			q.Scope.Paths = []string{"other/"}
			s.GitHubRequests[q.ID] = q
		},
		"delete approval": func(s *domain.State) { delete(s.GitHubRequests, "ghq") },
	} {
		t.Run(name, func(t *testing.T) {
			e := r.Transact(context.Background(), func(s *domain.State) error { mutate(s); return nil })
			if !errors.Is(e, ErrInvariant) {
				t.Fatalf("invariant accepted: %v", e)
			}
		})
	}
	if e := r.Transact(context.Background(), func(s *domain.State) error {
		g := s.GitHubGrants["ghg"]
		g.RevokedAt = &s.Now
		s.GitHubGrants[g.ID] = g
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := r.Transact(context.Background(), func(s *domain.State) error {
		g := s.GitHubGrants["ghg"]
		g.RevokedAt = nil
		s.GitHubGrants[g.ID] = g
		return nil
	}); !errors.Is(e, ErrInvariant) {
		t.Fatal("revocation undone")
	}
}

func TestGitHubPostgresInvariants(t *testing.T) { exerciseGitHubRepository(t, testPostgres(t)) }

func TestGitHubPostgresRawConstraints(t *testing.T) {
	p := testPostgres(t)
	seedGitHub(t, p)
	tests := []string{
		`INSERT INTO github_connections(payload) SELECT jsonb_set(jsonb_set(payload,'{ID}','"null-epoch"'),'{Epoch}','null') FROM github_connections WHERE id='ghc'`,
		`INSERT INTO github_grants(payload) SELECT jsonb_set(jsonb_set(payload,'{ID}','"null-expiry"'),'{ExpiresAt}','null') FROM github_grants WHERE id='ghg'`,
		`INSERT INTO github_grants(payload) SELECT jsonb_set(jsonb_set(payload,'{ID}','"future-epoch"'),'{Epoch}','99') FROM github_grants WHERE id='ghg'`,
		`INSERT INTO github_grants(payload) SELECT jsonb_set(jsonb_set(payload,'{ID}','"invalid-scope"'),'{Scope,Actions}','[null]') FROM github_grants WHERE id='ghg'`,
		`INSERT INTO github_requests(payload) SELECT jsonb_set(jsonb_set(jsonb_set(payload,'{ID}','"bad-approval"'),'{GrantID}','""'),'{Scope,Actions}','["files.write"]') FROM github_requests WHERE id='ghq'`,
		`DELETE FROM github_grants WHERE id='ghg'`,
		`UPDATE github_connections SET payload=jsonb_set(payload,'{RepositoryID}','100') WHERE id='ghc'`,
	}
	for _, query := range tests {
		if _, e := p.pool.Exec(context.Background(), query); e == nil {
			t.Errorf("raw SQL accepted: %s", query)
		}
	}
	// A new request may reference the same immutable binding but must agree with
	// its grant's scope, epoch and expiry, beyond the composite foreign key.
	if _, e := p.pool.Exec(context.Background(), `INSERT INTO github_grants(payload) SELECT jsonb_set(payload,'{ID}','"newgrant"') FROM github_grants WHERE id='ghg'`); e != nil {
		t.Fatal(e)
	}
	if _, e := p.pool.Exec(context.Background(), `INSERT INTO github_requests(payload) SELECT jsonb_set(jsonb_set(jsonb_set(payload,'{ID}','"scope-mismatch"'),'{GrantID}','"newgrant"'),'{Scope,Paths}','["private/"]') FROM github_requests WHERE id='ghq'`); e == nil {
		t.Fatal("approval scope mismatch accepted")
	}
}
