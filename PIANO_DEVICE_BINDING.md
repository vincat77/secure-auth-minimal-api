# Piano dettagliato: Device binding server-side (device_id persistente)

Obiettivo: vincolare refresh/sessioni a un device identificato da un `device_id` persistente (cookie HttpOnly separato), riducendo il rischio che un token rubato funzioni su altri device/UA.

## Assunzioni e regole
- Riutilizziamo il flusso remember/refresh esistente.
- `device_id` random (non PII), 32 byte Base64Url, salvato in DB.
- Binding: device_id + UA (opzionale IP /24).
- Cookie device: HttpOnly, SameSite=Strict (o Lax se serve), Secure in prod, Path="/".
- Non rimuoviamo il device_id su logout singolo (per riuso del device); logout-all può opzionalmente cancellarlo.

## Passi tecnici
1) Schema
   - Tabella `refresh_tokens`: aggiungere `device_id TEXT NULL`, `device_label TEXT NULL`.
   - Indice opzionale su (user_id, device_id) per lookup/cleanup.

2) Config
   - `Device:CookieName` (default `device_id`).
   - `Device:SameSite` (Strict/Lax).
   - `Device:RequireSecure` (default segue Cookie:RequireSecure/ambiente).
   - (Opzionale) `Device:PersistDays` se diversa dalla durata refresh; altrimenti usare la stessa durata del refresh.

3) Modello/DTO
   - Estendere `RefreshToken` con `DeviceId`, `DeviceLabel`.
   - Risposta login/refresh: opzionale `deviceIssued=true` e `deviceId` (non necessario di solito, meglio non esporlo).

4) Login con remember
   - Se cookie device assente: generare nuovo device_id, salvare nel refresh token, set-cookie device.
   - Se cookie presente: riusare device_id, salvarlo nei refresh creati.
   - Set-cookie device con HttpOnly, SameSite e Secure da config.

5) Endpoint /refresh
   - Leggere device_id dal cookie; se assente/diverso da stored → 401/step-up.
   - Verificare UA (già binding) e opzionale IP (/24) se configurato.
   - Ruotare il refresh mantenendo lo stesso device_id.

6) Logout / logout-all
   - Logout: revoca refresh; lascia device_id (per riconoscere il device in futuro).
   - Logout-all: revoca tutti i refresh utente; opzionale cancellare il cookie device (config).

7) Test xUnit
   - Login remember senza device cookie → riceve cookie device + refresh.
   - Refresh con device corretto → OK; device assente/diverso → 401.
   - Logout-all revoca refresh ma il device_id può restare; nuovo login ricrea refresh con device esistente.
   - Config device SameSite/RequireSecure rispettata.

8) UI WinForms
   - Nessuna modifica necessaria: CookieContainer gestisce device cookie. Log facoltativo di deviceIssued.
