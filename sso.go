package main

// Trusted-header single sign-on.
//
// When Statusnook runs behind an authenticating reverse proxy such as
// oauth2-proxy, the proxy passes the signed-in user's identity in request
// headers. With SSO_HEADER_AUTH=true, visiting /login signs that user in
// directly instead of showing the username/password form, and password login
// is switched off.
//
// Headers are only trusted when the request comes from SSO_TRUSTED_PROXY,
// so a client that reaches Statusnook directly cannot spoof them.
//
//	SSO_HEADER_AUTH      "true" to enable (default off: upstream behaviour)
//	SSO_TRUSTED_PROXY    comma-separated hostnames, IPs or CIDRs of the proxy (required)
//	SSO_EMAIL_HEADER     identity header (default X-Forwarded-Email)
//	SSO_GROUPS_HEADER    comma-separated groups header (default X-Forwarded-Groups)
//	SSO_ALLOWED_GROUPS   if set, the user must be in one of these groups
//	SSO_LOGOUT_URL       where to send the browser after logging out (optional)

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type ssoSettings struct {
	enabled       bool
	trustedProxy  []string
	emailHeader   string
	groupsHeader  string
	allowedGroups []string
	logoutURL     string
}

var sso = loadSSOSettings()

func splitList(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func envOr(key string, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func loadSSOSettings() ssoSettings {
	s := ssoSettings{
		enabled:       strings.EqualFold(os.Getenv("SSO_HEADER_AUTH"), "true"),
		trustedProxy:  splitList(os.Getenv("SSO_TRUSTED_PROXY")),
		emailHeader:   envOr("SSO_EMAIL_HEADER", "X-Forwarded-Email"),
		groupsHeader:  envOr("SSO_GROUPS_HEADER", "X-Forwarded-Groups"),
		allowedGroups: splitList(os.Getenv("SSO_ALLOWED_GROUPS")),
		logoutURL:     os.Getenv("SSO_LOGOUT_URL"),
	}
	if s.enabled && len(s.trustedProxy) == 0 {
		log.Fatalf("SSO_HEADER_AUTH is enabled but SSO_TRUSTED_PROXY is empty")
	}
	if s.enabled {
		log.Printf("sso: trusted-header login enabled (proxy %v, groups %v)", s.trustedProxy, s.allowedGroups)
	}
	return s
}

// fromTrustedProxy reports whether the TCP peer is one of the configured proxies.
func fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}
	for _, p := range sso.trustedProxy {
		if _, cidr, err := net.ParseCIDR(p); err == nil {
			if cidr.Contains(peer) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			if ip.Equal(peer) {
				return true
			}
			continue
		}
		// Hostname, e.g. a docker compose service name. Resolved per request
		// because container IPs change on restart.
		addrs, err := net.LookupIP(p)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.Equal(peer) {
				return true
			}
		}
	}
	return false
}

// ssoIdentity returns the proxy-asserted email, or an error explaining why
// the request can't be signed in.
func ssoIdentity(r *http.Request) (string, error) {
	if !fromTrustedProxy(r) {
		return "", errors.New("request did not come through the sign-in proxy")
	}
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(sso.emailHeader)))
	if email == "" {
		return "", errors.New("the sign-in proxy did not pass an identity")
	}
	if len(sso.allowedGroups) > 0 {
		member := false
		for _, g := range splitList(r.Header.Get(sso.groupsHeader)) {
			for _, allowed := range sso.allowedGroups {
				if g == allowed {
					member = true
				}
			}
		}
		if !member {
			return "", fmt.Errorf("%s is not in an allowed group", email)
		}
	}
	return email, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ssoLogin signs the proxy-asserted user in, creating a Statusnook user named
// after their email on first visit. SSO users get a random password nobody
// knows, so they can only ever sign in through the proxy.
func ssoLogin(w http.ResponseWriter, r *http.Request) {
	email, err := ssoIdentity(r)
	if err != nil {
		log.Printf("sso: refused: %s", err)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: " + err.Error() + "\n"))
		return
	}

	tx, err := rwDB.Begin()
	if err != nil {
		log.Printf("ssoLogin.Begin: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, userID, err := getPasswordHash(tx, email)
	if errors.Is(err, sql.ErrNoRows) {
		pw, err := randomToken()
		if err != nil {
			log.Printf("ssoLogin.randomToken: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("ssoLogin.GenerateFromPassword: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		userID, err = createUser(tx, email, string(hash))
		if err != nil {
			log.Printf("ssoLogin.createUser: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf("sso: created user %s", email)
	} else if err != nil {
		log.Printf("ssoLogin.getPasswordHash: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	token, err := randomToken()
	if err != nil {
		log.Printf("ssoLogin.randomToken: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomToken()
	if err != nil {
		log.Printf("ssoLogin.randomToken: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = createSession(tx, token, csrfToken, userID); err != nil {
		log.Printf("ssoLogin.createSession: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = tx.Commit(); err != nil {
		log.Printf("ssoLogin.Commit: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Short-lived: the proxy re-authenticates the browser anyway, and a
	// session should not outlive the SSO session by years.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().UTC().Add(12 * time.Hour),
		Secure:   BUILD == "release",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	log.Printf("sso: signed in %s", email)

	// "Manage this page" is an hx-boost link: ask htmx for a full page load.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/admin/alerts")
		return
	}
	http.Redirect(w, r, "/admin/alerts", http.StatusFound)
}
