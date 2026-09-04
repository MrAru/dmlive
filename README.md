#  dmlive

## Firefox cookie fallback

To let dmlive recover an expired configured video-site session from a logged-in
Firefox profile, add the following to `config.toml`:

```toml
cookies_from_browser = "firefox"
```

The configured cookie is checked at startup. If it is no longer logged in,
dmlive reads unexpired cookies from Firefox's default profile, validates them,
uses them for the current process, and atomically updates `bcookie` in the
configuration. Firefox must still have a valid logged-in session. No browser is
started and no cookie values are written to logs. Only the minimal login fields
`SESSDATA`, `bili_jct`, and `DedeUserID` are retained in `bcookie`.
