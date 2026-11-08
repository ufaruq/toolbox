package domain

// OwnerLoginInUse retains the links needed to revoke a session's replacements,
// even after an intermediate session expires. Call only inside a transaction.
func OwnerLoginInUse(st *State, tx OwnerLoginTransaction) bool {
	queue := []OwnerLoginTransaction{tx}
	seen := map[string]bool{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current.ID] {
			continue
		}
		seen[current.ID] = true
		if (current.Status == "pending" || current.Status == "exchanging") && st.Now.Before(current.ExpiresAt) {
			return true
		}
		if current.IssuedSessionID == "" {
			continue
		}
		if session, ok := st.Sessions[current.IssuedSessionID]; ok && st.Now.Before(session.ExpiresAt) {
			return true
		}
		for _, child := range st.OwnerLogins {
			if child.PreviousSessionID == current.IssuedSessionID {
				queue = append(queue, child)
			}
		}
	}
	return false
}
