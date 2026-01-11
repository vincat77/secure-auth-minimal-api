## Step 3A.4 - Pulizia, doc e verifica finale

**Obiettivo:** allineare documentazione/test e chiudere lo step CSRF refresh.

### Tasks
- Doc: aggiornare README/appsettings.guida per indicare che `/refresh` richiede header `X-Refresh-Csrf` (da response precedente).
- Valutare se in prod il token va restituito o solo in dev/test; documentare la scelta.
- Rimuovere eventuali log del token (mai loggare il segreto).
- Test: `dotnet test` completo verde; smoke manuale su login/confirm-mfa/refresh con header corretto e casi 403.

### Come affrontarlo
- Allineare gli helper di test per includere l’header automaticamente quando c’è un refresh token.
- Verificare che i cookie/SameSite/RequireSecure restino invariati.
- Se necessario, introdurre feature flag per compatibilità (non richiesto in dev).
