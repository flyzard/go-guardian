package auth

import (
	"context"
)

type contextKey string

const UserContextKey contextKey = "guardian.user"

// WithUser adds user to context
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, UserContextKey, user)
}

// UserFromContext retrieves user from context
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey).(*User)
	return user, ok
}
