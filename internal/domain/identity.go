package domain

import "strconv"

// IdentityKey preserves both component boundaries, including embedded separators.
func IdentityKey(issuer, subject string) string {
	return strconv.Itoa(len(issuer)) + ":" + issuer + subject
}

// ResolveIdentity resolves an exact primary or verified alias identity. Call only
// on a transaction snapshot. Ambiguous or malformed snapshots fail closed.
func ResolveIdentity(st *State, issuer, subject string) (User, bool) {
	if st == nil || issuer == "" || subject == "" {
		return User{}, false
	}
	var result User
	for _, u := range st.Users {
		if u.Issuer == issuer && u.Subject == subject {
			if result.ID != "" {
				return User{}, false
			}
			result = u
		}
	}
	if a, ok := st.IdentityAliases[IdentityKey(issuer, subject)]; ok {
		if result.ID != "" || a.Issuer != issuer || a.Subject != subject {
			return User{}, false
		}
		u, exists := st.Users[a.OwnerID]
		if !exists || u.ID == "" || u.ID != a.OwnerID {
			return User{}, false
		}
		result = u
	}
	return result, result.ID != ""
}

// IdentityForOwner returns the owner's unique identity at the requested issuer.
// More than one subject requires an explicit choice and cannot authorize approval.
func IdentityForOwner(st *State, ownerID, issuer string) (IdentityAlias, bool) {
	if st == nil || ownerID == "" || issuer == "" {
		return IdentityAlias{}, false
	}
	u, ok := st.Users[ownerID]
	if !ok || u.ID != ownerID {
		return IdentityAlias{}, false
	}
	var result IdentityAlias
	if u.Issuer == issuer {
		result = IdentityAlias{Issuer: u.Issuer, Subject: u.Subject, OwnerID: u.ID}
	}
	for k, a := range st.IdentityAliases {
		if a.OwnerID != ownerID || a.Issuer != issuer {
			continue
		}
		if k != IdentityKey(a.Issuer, a.Subject) || result.Subject != "" {
			return IdentityAlias{}, false
		}
		result = a
	}
	resolved, ok := ResolveIdentity(st, result.Issuer, result.Subject)
	return result, ok && resolved.ID == ownerID
}
