package core

import (
	"github.com/seatedro/guam/auth"
)

type ProviderUserAuth struct {
	providerId     string
	providerUserId string
	auth           auth.Auth
}

func NewProviderUserAuth(auth auth.Auth, providerId, providerUserId string) *ProviderUserAuth {
	provider := &ProviderUserAuth{
		auth:           auth,
		providerId:     providerId,
		providerUserId: providerUserId,
	}

	return provider
}

type (
	GuamUser                   auth.User
	GuamDatabaseUserAttributes auth.CreateUserOptions
)

func (p *ProviderUserAuth) GetExistingUser() (*auth.User, error) {
	key, err := p.auth.UseKey(p.providerId, p.providerUserId, nil)
	if err != nil {
		return nil, auth.NewGuamError(auth.AUTH_INVALID_KEY_ID, nil)
	}

	user, err := p.auth.GetUser(key.UserId)
	if err != nil {
		return nil, auth.NewGuamError(auth.AUTH_INVALID_KEY_ID, nil)
	}

	return user, nil
}

func (p *ProviderUserAuth) CreateKey(userId string) *auth.Key {
	opts := auth.CreateKeyOptions{
		UserId:         userId,
		ProviderId:     p.providerId,
		ProviderUserId: p.providerUserId,
		Password:       nil,
	}
	return p.auth.CreateKey(opts)
}

func (p *ProviderUserAuth) CreateUser(
	userId *string,
	attributes map[string]any,
) *auth.User {
	opts := auth.CreateUserOptions{
		UserId: userId,
		Key: &auth.CreateUserKey{
			ProviderId:     p.providerId,
			ProviderUserId: p.providerUserId,
			Password:       nil,
		},
		Attributes: attributes,
	}

	newUser := p.auth.CreateUser(opts)

	return newUser
}
