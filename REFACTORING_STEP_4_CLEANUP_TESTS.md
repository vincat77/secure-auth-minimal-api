## Step 4 - Pulizia finale e test

**Obiettivo:** completare la migrazione, allineare test e doc, verificare che non ci siano regressioni.
**Stato attuale:** filtri applicati in batch precedenti; possibili residui di controlli duplicati e test da aggiornare.
**Azione:** allineare test, documentazione e pipeline, eliminare duplicati residui.

- Consolidare i test sui filtri (`SessionFilter`, `CsrfFilter`, `MfaFilter`) e sugli endpoint migrati (200/401/403 invariati).
- Aggiornare helper di test per iniettare facilmente sessione/CSRF dove serve bypassare i filtri.
- Rimuovere controlli legacy rimasti negli endpoint (session/CSRF/MFA) già coperti dai filtri.
- Aggiornare documentazione interna/README con l’uso di `.RequireSession()/.RequireCsrf()/.RequireMfa()` per nuovi endpoint.
- Verificare ordine middleware → filtri (auth prima, CSRF filter dopo).
- Note operative dal codice:
  - Pipeline attuale (Program.cs): `UseCookieJwtAuth()` → `UseCsrfProtection()` → endpoint. I filtri devono assumere questa sequenza o essere coerenti con eventuale rimozione/sostituzione del middleware CSRF.
  - `CsrfMiddleware` oggi esclude alcune route pubbliche: se si passa a filtri, assicurarsi che la whitelisting sia equivalente o non necessaria sugli endpoint migrati.
  - Endpoint già migrati in batch 1/2 devono avere controlli duplicati rimossi (session/CSRF manuali).
  - Config/SameSite/RequireSecure non devono cambiare: i filtri non toccano cookie options, solo prerequisiti auth/CSRF/MFA.

Verifica finale:
- `dotnet test` completo.
- Smoke manuale su login/me/logout/refresh/mfa/reset per confermare nessuna regressione nei codici di risposta.
- Aggiungere/regolare test finali che coprano la catena filtri + endpoint (200/401/403 invariati) e che non restino controlli duplicati.

### Come affrontarlo
- Passare in rassegna endpoint e rimuovere eventuali controlli duplicati ancora presenti (session/CSRF/MFA) dopo l’applicazione dei filtri.
- Allineare la doc (README/appsettings.guida) e i commenti d’uso per i nuovi filtri/extension.
- Eseguire la suite completa (`dotnet test`) e uno smoke manuale sugli endpoint chiave; confermare l’ordine middleware → filtri → endpoint e, se necessario, valutare la rimozione/riuso del `CsrfMiddleware` in favore dei filtri.
