# Azioni codice dal threat model STRIDE (SecureAuthMinimalApi)

Questo piano elenca gli interventi puntuali sul codice per allineare il modello STRIDE allo stato reale.

## 1) Seed demo (rischio ambienti non demo)
- Verifica: `Seed:Enabled` è opt-in ma ancora attivabile fuori da Development (solo warning).
- Azione: aggiungere hard block in non-Development (throw o forzare false) oppure documentare chiaramente in appsettings.*.json che va lasciato false.

## 2) DataProtection key ring
- Verifica: chiavi persistite su `.dpkeys/` locale (fallback).
- Azione: rendere il path configurabile obbligatorio in non-Development e loggare/validare che sia persistente e condiviso tra istanze; considerare ACL/permessi sul filesystem.

## 3) JWT secret hardening
- Stato: guard-rail già presente (fail-fast su placeholder/corto).
- Azione: nessuna sul codice; aggiungere test/alert se vuoi enforcement più rigido (es. entropia minima) e documentare il requisito.

## 4) Rate limiting / brute force
- Verifica: login throttle presente; MFA challenge non ha rate limit dedicato; /refresh non ha throttle/flood guard.
- Azioni:
  - Aggiungere rate limit per MFA: max tentativi per IP/utente in finestra breve; 429 o blocco challenge.
  - Aggiungere throttle su /refresh (per IP/device) o reuse-delay minimo.

## 5) Audit/logging
- Verifica: login audit c’è; reset password ha logging limitato; nessun audit strutturato per refresh/logout/change-password.
- Azioni:
  - Introdurre log strutturati per: refresh (success/fail), logout/logout-all, change-password, password reset (request/confirm/fail).
  - Considerare un logger dedicato “security/audit” per separare il rumore.

## 6) Information disclosure (reset token in dev/test)
- Verifica: `PasswordReset:IncludeTokenInResponseForTesting` può esporre token in dev/test.
- Azioni:
  - Aggiungere guardia: consentire solo in Development o con flag test esplicito; log warning quando attivo.
  - Test: assicurare che in non-Development il campo non venga mai ritornato.

## 7) DoS / risorse
- Verifica: cleanup ok; nessuna protezione su flood /refresh e MFA; login throttle sì.
- Azioni (in parte sovrapposte a punto 4): introdurre limiti per /refresh e MFA; opzionale: circuit-breaker su IP che generano troppi 401/429.

## 8) Documentazione/config
- Aggiornare appsettings.guida.md con:
  - Seed:Enabled = false in prod; demo solo in Dev.
  - DataProtection:KeysPath obbligatorio in prod (persistente).
  - IncludeTokenInResponseForTesting solo in Dev.
  - Requisiti Jwt:SecretKey (no placeholder, min 32+ char).
