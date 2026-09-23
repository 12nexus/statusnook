# Single sign-on behind an authenticating proxy (12nexus fork)

This fork adds trusted-header login, so Statusnook can sit behind
[oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) (or any proxy that
passes the signed-in user in headers) without a second username/password.
It is **off by default**; with no `SSO_*` variables set, Statusnook behaves
exactly like upstream.

## What changes when it's on

- `GET /login` (the "Manage this page" link) signs in the user named in the
  identity header. On first visit a Statusnook user is created, named after
  the email, with a random password nobody knows. Sessions last 12 hours.
- Headers are trusted only when the TCP peer is `SSO_TRUSTED_PROXY`; anything
  else gets 403. Never publish Statusnook's own port when using this.
- `POST /login` (password login) returns 403.
- Log out can hand off to the proxy's sign-out (`SSO_LOGOUT_URL`).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SSO_HEADER_AUTH` | off | `true` to enable |
| `SSO_TRUSTED_PROXY` | required | Comma-separated hostnames, IPs or CIDRs of the proxy; hostnames are resolved per request |
| `SSO_EMAIL_HEADER` | `X-Forwarded-Email` | Identity header |
| `SSO_GROUPS_HEADER` | `X-Forwarded-Groups` | Comma-separated groups |
| `SSO_ALLOWED_GROUPS` | empty (any) | Require one of these groups |
| `SSO_LOGOUT_URL` | empty | Where Log out sends the browser |

## Example (docker compose with oauth2-proxy)

```yaml
services:
  statusnook:
    build: https://github.com/12nexus/statusnook.git#sso-header-auth
    environment:
      SSO_HEADER_AUTH: "true"
      SSO_TRUSTED_PROXY: oauth2-proxy
      SSO_ALLOWED_GROUPS: admins
      SSO_LOGOUT_URL: /oauth2/sign_out
  oauth2-proxy:
    image: quay.io/oauth2-proxy/oauth2-proxy:v7.12.0
    # provider/issuer/client settings..., plus:
    #   upstreams = ["http://statusnook:8000/"]
    #   pass_user_headers = true
    #   oidc_groups_claim = "groups"
    ports: ["127.0.0.1:3410:4180"]
```

First-time setup (the setup wizard) works as upstream. Anything that logs in
with a password, such as scripts, needs SSO turned off while it runs.

Code: `sso.go`, plus hooks at the top of `getLogin` and `postLogin` and at the
end of `logout` in `main.go`.

Used by https://status.apps.12nexusbpo.com (12nexus/nexgen-credits-monitor).
