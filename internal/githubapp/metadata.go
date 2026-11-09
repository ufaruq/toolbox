package githubapp

import (
	"context"
	"encoding/json"
	"github.com/ufaruq/toolbox/internal/strict"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Repository struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (i *Issuer) metadata(ctx context.Context, token, path string, out any) error {
	req, e := http.NewRequestWithContext(ctx, "GET", i.baseURL+path, nil)
	if e != nil {
		return ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "toolbox-github-app")
	r, e := i.http.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 || validMetadata(b, out) != nil {
		return ErrUnavailable
	}
	return nil
}

// Repositories uses an independently revoked metadata-only discovery token.
// This control-plane credential must never be used for operation execution.
func (i *Issuer) Repositories(ctx context.Context, installationID int64) (result []Repository, resultErr error) {
	if installationID <= 0 {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	jwt, e := i.jwt()
	if e != nil {
		return nil, e
	}
	var installation struct {
		ID                  int64  `json:"id"`
		AppID               int64  `json:"app_id"`
		RepositorySelection string `json:"repository_selection"`
	}
	if i.metadata(ctx, jwt, "/app/installations/"+strconv.FormatInt(installationID, 10), &installation) != nil || installation.ID != installationID || strconv.FormatInt(installation.AppID, 10) != i.appID || (installation.RepositorySelection != "selected" && installation.RepositorySelection != "all") {
		return nil, ErrScope
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", i.baseURL+"/app/installations/"+strconv.FormatInt(installationID, 10)+"/access_tokens", strings.NewReader(`{"permissions":{"metadata":"read"}}`))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "toolbox-github-app")
	r, e := i.http.Do(req)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 || r.StatusCode != 201 {
		return nil, ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if strict.Decode(b, &fields) != nil {
		return nil, ErrScope
	}
	var token string
	if json.Unmarshal(fields["token"], &token) != nil || !validToken(token) {
		return nil, ErrScope
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if i.Revoke(cleanup, token) != nil {
			result = nil
			resultErr = ErrUnavailable
		}
	}()
	var p map[string]string
	var selection string
	var expiry time.Time
	if strict.Decode(fields["permissions"], &p) != nil || len(p) != 1 || p["metadata"] != "read" || json.Unmarshal(fields["repository_selection"], &selection) != nil || selection != installation.RepositorySelection || json.Unmarshal(fields["expires_at"], &expiry) != nil || !expiry.After(i.now().Add(time.Minute)) || expiry.After(i.now().Add(time.Hour+time.Minute)) {
		return nil, ErrScope
	}
	repos := []Repository{}
	seen := map[int64]bool{}
	for page := 1; page <= 10; page++ {
		var result struct {
			Total        int          `json:"total_count"`
			Repositories []Repository `json:"repositories"`
		}
		if i.metadata(ctx, token, "/installation/repositories?per_page=100&page="+strconv.Itoa(page), &result) != nil || result.Total > 1000 {
			return nil, ErrUnavailable
		}
		for _, repo := range result.Repositories {
			if repo.ID <= 0 || repo.Name == "" || repo.Owner.Login == "" || seen[repo.ID] {
				return nil, ErrScope
			}
			seen[repo.ID] = true
			repos = append(repos, repo)
		}
		if len(result.Repositories) < 100 || len(repos) == result.Total {
			if len(repos) != result.Total {
				return nil, ErrScope
			}
			return repos, nil
		}
	}
	return nil, ErrUnavailable
}

// GetRepositoryMetadata exposes only fixed GitHub GET metadata endpoints to the
// runtime. It is not a general provider-operation transport.
func (i *Issuer) GetRepositoryMetadata(ctx context.Context, token, owner, repo, suffix string, out any) error {
	if strings.ContainsAny(owner+repo, "/?#%\\") || owner == "" || repo == "" || (suffix != "" && !strings.HasPrefix(suffix, "/")) || strings.ContainsAny(suffix, "?#") {
		return ErrConfiguration
	}
	return i.metadata(ctx, token, "/repos/"+owner+"/"+repo+suffix, out)
}

func validMetadata(b []byte, out any) error {
	var m map[string]json.RawMessage
	if strict.Decode(b, &m) != nil {
		return ErrUnavailable
	}
	return json.Unmarshal(b, out)
}
