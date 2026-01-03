# Piano azione: claim profilo in id_token (name, given_name, family_name, email, picture)

## Vincoli e contesto
- Nessuna migrazione retrocompatibile necessaria: prodotto in sviluppo, schema modificabile direttamente.
- Id token deve sempre includere i nuovi claim (non legati a scope), aggiungendo anche `picture` come URL avatar.
- Commit granulari, uno per ogni gruppo di modifiche.

## Step previsti
1) **Allinea modello dati e schema**  
   - Aggiungi colonne profilo (name/full name, given_name, family_name, email già presente, picture URL) nelle entità/DTO e nello schema creato da `DbInitializer`.  
   - Aggiorna seed demo per valorizzare i nuovi campi.  
   - Commit: dati/schema profilo.

2) **Acquisizione/validazione input utente**  
   - Estendi modelli request/response di registrazione e qualsiasi DTO utente per includere i campi profilo + picture.  
   - Aggiungi validazioni minime (non vuoti dove serve, lunghezze/URL picture).  
   - Aggiorna servizi/repository per salvare i nuovi campi.  
   - Commit: input/validation profilo.

3) **Emissione id_token con claim profilo**  
   - Aggiorna `IdTokenService` e `Program` per emettere i claim `name`, `given_name`, `family_name`, `email`, `picture` in modo stabile.  
   - Aggiorna configurazione/guida se necessario (e.g., default picture?).  
   - Commit: id_token claim profilo.

4) **UI/Client e test**  
   - Aggiorna client WinForms (view/submit dei nuovi campi, mostra id_token arricchito) se rilevante.  
   - Aggiorna test integrazione/unitari e aggiungi molti xUnit test dedicati (registrazione con nuovi campi, validazione, emissione id_token con claim profilo, presenza/assenza picture/email).  
   - Commit: client+test profilo.

5) **Documentazione**  
   - Aggiorna `DESCRIZIONE_SOLUTION.md` e/o `appsettings.guida.md` con i nuovi campi/claim e comportamento.  
   - Commit: docs profilo id_token.
