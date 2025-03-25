package auth

type SessionManager struct {
	SessionNonces map[string]string
}
