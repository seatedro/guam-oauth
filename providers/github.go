package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/seatedro/guam-oauth/core"
	"github.com/seatedro/guam-oauth/utils"
	"go.uber.org/zap"

	"github.com/seatedro/guam/auth"
)

type Config struct {
	RedirectUri  *string
	ClientId     string
	ClientSecret string
	Scope        []string
}

const PROVIDER_GITHUB = "github"

var logger *zap.SugaredLogger

func Github(auth auth.Auth, config Config) *GithubAuth {
	if auth.Experimental.DebugMode {
		l, err := zap.NewDevelopment()
		if err != nil {
			logger = zap.NewNop().Sugar()
		}
		logger = l.Sugar()
	} else {
		l, err := zap.NewProduction(zap.IncreaseLevel(zap.ErrorLevel))
		if err != nil {
			logger = zap.NewNop().Sugar()
		}
		logger = l.Sugar()
	}

	return NewGithubAuth(auth, config)
}

type GithubAuth struct {
	config Config
	auth   auth.Auth
}

func NewGithubAuth(auth auth.Auth, config Config) *GithubAuth {
	return &GithubAuth{auth: auth, config: config}
}

func (g *GithubAuth) GetAuthorizationURL() (*core.GetAuthorizationUrlResponse, error) {
	scope := []string{}
	if g.config.Scope != nil {
		scope = g.config.Scope
	}
	return core.CreateOauth2AuthorizationURL(core.CreateOauth2AuthorizationURLOptions{
		URL: "https://github.com/login/oauth/authorize",
		Options: struct {
			RedirectUri *string
			ClientId    string
			Scope       []string
		}{
			ClientId:    g.config.ClientId,
			Scope:       scope,
			RedirectUri: g.config.RedirectUri,
		},
	})
}

func (g *GithubAuth) ValidateCallback(code string) (*GithubUserAuth, error) {
	githubTokens, err := g.ValidateAuthorizationCode(code)
	if err != nil {
		return nil, err
	}
	githubUser := getGithubUser(githubTokens.AccessToken)
	return NewGithubUserAuth(g.auth, *githubTokens, *githubUser), nil
}

func (g *GithubAuth) ValidateAuthorizationCode(code string) (*GithubTokens, error) {
	opts := core.ValidateOauth2AuthorizationCodeOptions{
		AuthorizationCode: code,
		URL:               "https://github.com/login/oauth/access_token",
		Options: core.Oauth2ValidationOptions{
			ClientId:    g.config.ClientId,
			RedirectUri: nil,
			ClientPassword: &core.Oauth2ClientPassword{
				ClientSecret:     g.config.ClientSecret,
				AuthenticateWith: "client_secret",
			},
		},
	}
	response, err := core.ValidateOauth2AuthorizationCode(opts)
	if err != nil {
		logger.Errorf("Error validating authorization code: %v", err)
		return nil, err
	}

	var tokens AccessTokenResponseBody
	err = json.Unmarshal(*response, &tokens)
	if err != nil {
		logger.Errorf("Error unmarshalling access token response body: %v", err)
		return nil, err
	}

	if tokens.RefreshToken != nil {
		return &GithubTokens{
			AccessToken:           tokens.AccessToken,
			AccessTokenExpiresIn:  tokens.ExpiresIn,
			RefreshToken:          tokens.RefreshToken,
			RefreshTokenExpiresIn: tokens.RefreshTokenExpiresIn,
		}, nil
	}

	if tokens.AccessToken == "" {
		logger.Errorln("Error getting access token")
		return nil, errors.New("error getting access token")
	}
	return &GithubTokens{
		AccessToken:          tokens.AccessToken,
		AccessTokenExpiresIn: tokens.ExpiresIn,
	}, nil
}

func getGithubUser(accessToken string) *GithubUser {
	h := http.Header{}
	authHeader, err := utils.AuthorizationHeader(
		utils.AUTHORIZATION_HEADER_TYPE_BEARER,
		accessToken,
	)
	if err != nil {
		logger.Errorf("Error getting authorization header: %v", err)
		return nil
	}
	h.Add("Authorization", authHeader)
	url, err := url.Parse("https://api.github.com/user")
	if err != nil {
		logger.Errorf("Error parsing url: %v", err)
		return nil
	}
	githubUserReq := http.Request{
		Method: http.MethodGet,
		URL:    url,
		Header: h,
	}

	response, err := utils.HandleRequest(githubUserReq)
	if err != nil {
		logger.Errorf("Error getting github user: %v", err)
		return nil
	}

	var githubUser GithubUser
	err = json.Unmarshal(*response, &githubUser)
	if err != nil {
		logger.Errorf("Error unmarshalling github user: %v", err)
		return nil
	}

	return &githubUser
}

type AccessTokenResponseBody struct {
	RefreshToken          *string `json:"refresh_token"`
	ExpiresIn             *int64  `json:"expires_in"`
	RefreshTokenExpiresIn *int64  `json:"refresh_token_expires_in"`
	AccessToken           string  `json:"access_token"`
}

type GithubUserAuth struct {
	*core.ProviderUserAuth
	GithubTokens GithubTokens
	GithubUser   GithubUser
}

func NewGithubUserAuth(
	auth auth.Auth,
	githubTokens GithubTokens,
	githubUser GithubUser,
) *GithubUserAuth {
	return &GithubUserAuth{
		ProviderUserAuth: core.NewProviderUserAuth(
			auth,
			PROVIDER_GITHUB,
			fmt.Sprintf("%d", githubUser.ID),
		),
		GithubTokens: githubTokens,
		GithubUser:   githubUser,
	}
}

type GithubTokens struct {
	RefreshToken          *string
	AccessTokenExpiresIn  *int64
	RefreshTokenExpiresIn *int64
	AccessToken           string
}

type GithubUser struct {
	PrivateGithubUser
	PublicGithubUser
}

// PublicGithubUser represents a public GitHub user.
type PublicGithubUser struct {
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Company     *string    `json:"company"`
	Hireable    *bool      `json:"hireable"`
	Blog        *string    `json:"blog"`
	Email       *string    `json:"email"`
	SuspendedAt *time.Time `json:"suspended_at,omitempty"`
	Plan        *struct {
		Name          string `json:"name"`
		Space         int    `json:"space"`
		PrivateRepos  int    `json:"private_repos"`
		Collaborators int    `json:"collaborators"`
	} `json:"plan,omitempty"`
	TwitterUsername   *string `json:"twitter_username,omitempty"`
	Bio               *string `json:"bio"`
	Name              *string `json:"name"`
	Location          *string `json:"location"`
	GravatarID        *string `json:"gravatar_id"`
	FollowersURL      string  `json:"followers_url"`
	ReposURL          string  `json:"repos_url"`
	EventsURL         string  `json:"events_url"`
	GistsURL          string  `json:"gists_url"`
	Login             string  `json:"login"`
	FollowingURL      string  `json:"following_url"`
	NodeID            string  `json:"node_id"`
	OrganizationsURL  string  `json:"organizations_url"`
	AvatarURL         string  `json:"avatar_url"`
	URL               string  `json:"url"`
	ReceivedEventsURL string  `json:"received_events_url"`
	HTMLURL           string  `json:"html_url"`
	Type              string  `json:"type"`
	StarredURL        string  `json:"starred_url"`
	SubscriptionsURL  string  `json:"subscriptions_url"`
	Following         int     `json:"following"`
	PublicRepos       int     `json:"public_repos"`
	PublicGists       int     `json:"public_gists"`
	Followers         int     `json:"followers"`
	ID                int     `json:"id"`
	SiteAdmin         bool    `json:"site_admin"`
}

// PrivateGithubUser represents a private GitHub user.
type PrivateGithubUser struct {
	BusinessPlus            *bool   `json:"business_plus,omitempty"`
	LdapDN                  *string `json:"ldap_dn,omitempty"`
	Collaborators           int     `json:"collaborators"`
	DiskUsage               int     `json:"disk_usage"`
	OwnedPrivateRepos       int     `json:"owned_private_repos"`
	PrivateGists            int     `json:"private_gists"`
	TotalPrivateRepos       int     `json:"total_private_repos"`
	TwoFactorAuthentication bool    `json:"two_factor_authentication"`
}
