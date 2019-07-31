package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/casbin/casbin"
	"github.com/labstack/echo/v4"
	"gopkg.in/cas.v2"
	"net/url"
	"strings"
)

type (
	Cas struct {
		Base      `json:",squash" yaml:",squash"`
		CasConfig `json:",squash" yaml:",squash"`
	}

	CasConfig struct {
		URL string `json:"url" yaml:"url"`
		CasbinCfg CasbinConfig `yaml:"casbin"`
	}

	CasbinConfig struct {
		Model string `yaml:"model"`
		Policy string `yaml:"policy"`
		SubjectAttribute string `yaml:"subject_attr"`
	}
)

func (cfg CasbinConfig) Enforcer() (*casbin.Enforcer, error) {
	if cfg.Model == "" {
		return nil, errors.New("invalid casbin model")
	}
	return casbin.NewEnforcerSafe(cfg.Model, cfg.Policy)
}

func newCasClient(c CasConfig) (*cas.Client, error) {
	casURL, err := url.Parse(c.URL)
	if err != nil {
		return nil, err
	}

	return cas.NewClient(&cas.Options{
		URL:         casURL,
	}), nil
}

type casCtxKey int

type casbinMiddleware struct {
	Enforcer *casbin.Enforcer
	SubjectFunc func(c echo.Context) string
}

func (cb *casbinMiddleware) MiddlewareFunc() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func (c echo.Context) error {
			if cb.Enforcer == nil {
				return echo.ErrForbidden
			}
			sub := cb.SubjectFunc(c)
			if sub == "" {
				return echo.ErrUnauthorized
			}
			if allow, _ := cb.Enforcer.EnforceSafe(sub, "*"); allow {
				return next(c)
			}
			return echo.ErrForbidden
		}
	}
}

func newCasbinMiddleware(cfg CasbinConfig) (*casbinMiddleware, error) {
	enforcer, err := cfg.Enforcer()
	if err != nil || enforcer == nil {
		return nil, err
	}
	sub := attrGetter(cfg.SubjectAttribute)
	return &casbinMiddleware{
		Enforcer: enforcer,
		SubjectFunc: sub,
	}, nil
}

const (
	CasUsernameCtxKey casCtxKey = iota
	CasAttributesCtxKey
)

func newCasMiddleware(client *cas.Client) echo.MiddlewareFunc {
	casHandle := echo.WrapMiddleware(client.Handle)
	casHandler := echo.WrapMiddleware(client.Handler)
	authMid := func (next echo.HandlerFunc) echo.HandlerFunc {
		return casHandle(casHandler(next))
	}
	moveAttrToCtx := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			attr := cas.Attributes(r)
			username := cas.Username(r)
			c.Set("casAttributes", attr)
			c.Set("casUsername", username)
			newCtx := context.WithValue(r.Context(), CasUsernameCtxKey, username)
			newCtx = context.WithValue(newCtx, CasAttributesCtxKey, attr)
			r.Header.Set("X-CAS-User", username)
			for k, v := range(attr) {
				r.Header.Set(fmt.Sprintf("X-CAS-Attr-%s", k), strings.Join(v, " "))
			}
			c.SetRequest(r.WithContext(newCtx))
			return next(c)
		}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return authMid(moveAttrToCtx(next))
	}
}

func getUsername(c echo.Context) string {
	r := c.Request()
	username, _ := r.Context().Value(CasUsernameCtxKey).(string)
	return username
}

func getCasAttributes(c echo.Context) cas.UserAttributes {
	return c.Request().Context().Value(CasAttributesCtxKey).(cas.UserAttributes)
}

func attrGetter(attr string) func(c echo.Context) string {
	if attr == "" {
		return getUsername
	}
	return func(c echo.Context) string {
		attributes := getCasAttributes(c)
		if attributes == nil {
			return ""
		}
		return attributes.Get(attr)
	}
}

func internalErrorMid(_ echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return echo.ErrInternalServerError
	}
}

func (r *Cas) Initialize() {
	client, err := newCasClient(r.CasConfig)
	if err != nil {
		r.Middleware = internalErrorMid
		return
	}
	casMid := newCasMiddleware(client)
	casbinMid, err := newCasbinMiddleware(r.CasbinCfg)
	if err != nil {
		r.Middleware = casMid
		return
	}
	casbinMidFunc := casbinMid.MiddlewareFunc()
	mid := func(next echo.HandlerFunc) echo.HandlerFunc {
		return casMid(casbinMidFunc(next))
	}
	r.Middleware = mid
}

func (r *Cas) Update(p Plugin) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.CasConfig = p.(*Cas).CasConfig
	r.Initialize()
}

func (*Cas) Priority() int {
	return -1
}

func (r *Cas) Process(next echo.HandlerFunc) echo.HandlerFunc {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.Middleware(next)
}
