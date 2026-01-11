## Smoke test plan (post filtri e CSRF refresh)

### Login + refresh con header
- POST `/login` con `RememberMe=true`.
- Recupera `refresh_token`, `device_id` dai cookie e `refreshCsrfToken` dal payload.
- POST `/refresh` con cookie + header `X-Refresh-Csrf` corretto → atteso 200 e nuovo `refreshCsrfToken` in response.

### Refresh senza header
- Ripeti login/remember.
- POST `/refresh` senza `X-Refresh-Csrf` → atteso 403.

### Refresh header errato
- Ripeti login/remember.
- POST `/refresh` con header `X-Refresh-Csrf: wrong` → atteso 403.

### MFA flow + refresh
- Utente con MFA: /login → challengeId.
- /login/confirm-mfa con TOTP → ricevi cookie, `refreshCsrfToken`.
- /refresh con header corretto → atteso 200 e nuovo token.

### Change email
- Utente loggato: POST `/me/email` con header `X-CSRF-Token` valido → atteso 200 (in dev payload include `confirmToken`).
- Senza header → atteso 403.

### Logout/logout-all/change-password
- Endpoint con sessione + header CSRF valido → 200.
- Senza header CSRF → 403.

### Verifica cookie/security
- Controlla Set-Cookie per `access_token`/`refresh_token`/`device_id`: HttpOnly, SameSite coerente, Secure (true in non-dev).
- Conferma che `/refresh` richiede sempre `X-Refresh-Csrf`.
