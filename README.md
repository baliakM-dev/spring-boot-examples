# BFF + OIDC (Keycloak) + Session Cookies — Login/Logout Flow (Spring Boot 4 + Vue)

Tento projekt používa architektúru **BFF (Backend For Frontend)** so **server-side session** a **OIDC loginom cez Keycloak**.  
Frontend (Vue) **nepoužíva JWT tokeny** na autentifikáciu — autentifikácia je riešená cez **HttpOnly session cookie**.

---

## Komponenty a porty

- **Frontend (Vue)**: `http://localhost:3000`
- **Backend / BFF (Spring Boot 4.0.0)**: `http://localhost:8080`
- **Keycloak (OIDC Provider)**: `http://localhost:8081`

---

## Quick start (DEV)

### Požadované ENV premenné
- `KEYCLOAK_CLIENT_SECRET=<SECRET>`
- `KEYCLOAK_ISSUER_URI=http://localhost:8081/realms/my_realm`
- `APP_FRONTEND_URL=http://localhost:3000`

### Spustenie
1. Spusti Keycloak na `http://localhost:8081`
2. Spusti backend na `http://localhost:8080`
3. Spusti frontend na `http://localhost:3000`

### Overenie
- Otvor `http://localhost:3000`
- Po kliknutí na protected route (napr. Admin/HR) prebehne redirect na Keycloak login
- Po návrate FE zavolá `GET /api/me` a zobrazí roly

---

## Keycloak konfigurácia (minimum)

### Klient (OIDC)
- Client type: OIDC
- Flow: Authorization Code
- Redirect URI:
  - DEV: `http://localhost:8080/login/oauth2/code/keycloak`
- Post logout redirect URI:
  - DEV: `http://localhost:3000/`
- Web origins:
  - DEV: `http://localhost:3000` (ak používaš CORS)

### Role claim
Aplikácia očakáva claim `roles` (Collection/String list).
- napr. `roles: ["admin","hr"]`
Backend to normalizuje na `ADMIN/HR`.

---

## Prečo BFF + session cookies (bez JWT na FE)

### Hlavné dôvody
- **Žiadne access/refresh tokeny v prehliadači** (žiadne `localStorage`, `sessionStorage`).
- **Client secret ostáva na serveri** (nikdy nejde do JS bundle).
- **CSRF je riešené štandardne** (XSRF cookie + header).
- **Jednoduchý runtime model**: backend autorizuje requesty podľa session.

### Bezpečnostný profil
- Pri “JWT v storage” platí: **XSS → krádež tokenu → použitie mimo browsera** (často najhorší scenár).
- Pri BFF session: XSS je stále problém, ale útočník typicky nezíska “prenášateľný bearer token”.
- Preto v PROD je kľúčové mať silné XSS mitigácie (najmä CSP bez `unsafe-inline`).

---

# Login flow (podrobne)

Používame **OAuth2 Authorization Code Flow** s OIDC, kde OAuth klient je **backend** (nie frontend).

## Krokový popis (čo sa deje)
1. Používateľ otvorí frontend (`/`).
2. Frontend zavolá `GET /api/me` s `credentials: include`.
3. Backend zistí, že user nie je autentifikovaný → vráti redirect na OIDC login.
4. Browser ide na backend endpoint `/oauth2/authorization/keycloak`.
5. Backend vygeneruje `state` a `nonce`, uloží ich server-side (session) a redirectne na Keycloak `/auth`.
6. Keycloak spraví login (UI/SSO).
7. Keycloak redirectne späť na backend callback `/login/oauth2/code/keycloak?code=...&state=...`.
8. Backend overí `state`, potom spraví **server-to-server** výmenu `code → tokeny` (Token endpoint).
9. Backend vytvorí autentifikovanú session (SecurityContext v session), namapuje roly z claimu `roles`.
10. Backend redirectne späť na frontend (`APP_FRONTEND_URL`).
11. Frontend znova zavolá `/api/me` a dostane user info + roly.

---

## Login flow — detailný diagram
```mermaid
 sequenceDiagram
  autonumber
  participant Browser as User/Browser
  participant FE as Frontend (3000)
  participant BFF as Backend/BFF (8080)
  participant KC as Keycloak (8081)

  Browser->>FE: GET /
  FE-->>Browser: App loaded

  FE->>BFF: GET /api/me
  BFF-->>FE: 401/302 (login)

  Browser->>BFF: GET /oauth2/authorization/keycloak
  Note over BFF: Create state + nonce\nStore in session
  BFF-->>Browser: 302 -> KC /auth

  Browser->>KC: GET /auth (OIDC login)
  KC-->>Browser: 302 -> BFF callback (code, state)

  Browser->>BFF: GET /login/oauth2/code/keycloak
  Note over BFF: Validate state
  BFF->>KC: POST /token (server-to-server)
  KC-->>BFF: tokens

  Note over BFF: Create session\nMap roles -> ROLE_ADMIN/ROLE_HR\nSet cookies
  BFF-->>Browser: 302 -> FE /
  Note over Browser: Cookies for BFF:\nJSESSIONID (HttpOnly)\nXSRF-TOKEN

  FE->>BFF: GET /api/me
  BFF-->>FE: 200 me payload (roles)
```

**Kroky v diagrame (po bodoch):**
1. Browser načíta FE (`GET /`).
2. FE zavolá backend `GET /api/me` – kontrola, či existuje prihlásená session.
3. Ak session neexistuje, backend vráti `401/302` a začne login flow.
4. Browser ide na `/oauth2/authorization/keycloak` (štart OIDC).
5. Backend vytvorí `state` + `nonce`, uloží ich do session a redirectne na Keycloak `/auth`.
6. Keycloak spraví login a redirectne späť na backend callback s `code` + `state`.
7. Backend overí `state`, potom server-to-server zavolá Keycloak `POST /token`.
8. Backend vytvorí autentifikovanú session a namapuje roly z claimu `roles` na `ROLE_ADMIN/ROLE_HR`.
9. Backend nastaví cookies `JSESSIONID` (HttpOnly) a `XSRF-TOKEN` (CSRF) a pošle redirect na FE.
10. FE znova zavolá `GET /api/me` a dostane user payload + roly.
    
---

# Logout flow (podrobne)

Logout je kombinácia:
- lokálneho logoutu (invalidate session v BFF)
- SSO logoutu (Keycloak end-session / RP-initiated logout)

## Krokový popis
1. User klikne Logout vo FE.
2. FE pošle `POST /logout` na BFF, pridá:
   - `Cookie: JSESSIONID=...`
   - `Header: X-XSRF-TOKEN: <hodnota z cookie XSRF-TOKEN>`
3. BFF overí CSRF token.
4. BFF invaliduje session.
5. BFF redirectne browser na Keycloak logout endpoint s `post_logout_redirect_uri` späť na FE.
6. Keycloak zruší SSO session a redirectne späť na FE.

---

## Logout flow — diagram (Mermaid)

```mermaid
sequenceDiagram
  autonumber
  participant U as User/Browser
  participant FE as Frontend (3000)
  participant BFF as Backend/BFF (8080)
  participant KC as Keycloak (8081)

  Note over U,FE: User clicks Logout
  FE->>BFF: POST /logout (with CSRF + cookies)
  Note over BFF: Verify CSRF\nInvalidate session
  BFF-->>U: 302 -> KC end-session

  U->>KC: GET /logout (post_logout_redirect_uri=FE)
  Note over KC: Clear SSO session
  KC-->>U: 302 -> FE /

  FE->>BFF: GET /api/me
  BFF-->>FE: 401/302 (not authenticated)
```
**Kroky v logout diagrame (po bodoch):**
1. Používateľ klikne **Logout** vo fronte.
2. **FE → BFF:** Frontend pošle `POST /logout` **s cookies** (session) a **CSRF headerom** `X-XSRF-TOKEN`.
3. **BFF (Note):** Backend overí CSRF token (ak nesedí, request odmietne) a potom invaliduje session (lokálny logout).
4. **BFF → U:** Backend vráti `302` redirect na Keycloak end-session endpoint (aby sa zrušilo aj SSO prihlásenie).
5. **U → KC:** Browser zavolá Keycloak logout endpoint s `post_logout_redirect_uri` nastaveným na FE.
6. **KC (Note):** Keycloak zruší SSO session cookies.
7. **KC → U:** Keycloak presmeruje používateľa späť na frontend (`302 -> FE /`).
8. **FE → BFF:** Frontend zavolá `GET /api/me` (kontrola prihlásenia po logoute).
9. **BFF → FE:** Backend už nemá session → vráti `401/302` (user je odhlásený, prípadne sa spustí login flow).
    
---

## API kontrakt

### GET /api/me
- Auth: vyžaduje autentifikovanú session (JSESSIONID)
- Response (príklad):
json { "username": "example.user", "name": "Example User", "email": "example.user@example.invalid", "roles": ["ADMIN", "HR"] }

---
# Variant A: Role mapping (UPPERCASE)

- Keycloak claim: `roles` (napr. `["admin","hr"]`)
- Backend mapuje na authorities:
  - `ROLE_ADMIN`
  - `ROLE_HR`
- `GET /api/me` vracia:
  - `roles: ["ADMIN","HR"]`

### Backend authorization príklady
- `.requestMatchers("/api/admin/**").hasRole("ADMIN")`
- `.requestMatchers("/api/hr/**").hasAnyRole("HR","ADMIN")`

---

# DEV vs PROD — tabuľky (cookies, CSRF, CORS, CSP, HSTS)

## 1) Cookies (JSESSIONID, XSRF-TOKEN)

| Položka | DEV | PROD | Prečo |
|---|---|---|---|
| `JSESSIONID` `HttpOnly` | ✅ `true` | ✅ `true` | JS ho nevie čítať → menší dopad XSS na krádež session. |
| `JSESSIONID` `Secure` | ⚠️ `false` (ak bez TLS) | ✅ `true` | Cookie iba cez HTTPS. |
| `JSESSIONID` `SameSite` | ✅ `Lax` | ✅ `Lax` (zvyčajne) | Funguje s OIDC redirectmi + brzdí veľa CSRF scenárov. |
| `XSRF-TOKEN` `HttpOnly` | ❌ `false` | ❌ `false` | FE musí token čítať a poslať v headeri. |
| `XSRF-TOKEN` `Secure` | ⚠️ `false` (ak bez TLS) | ✅ `true` | Ochrana pred odpočúvaním. |
| `XSRF-TOKEN` `SameSite` | ✅ `Lax` | ✅ `Lax` | Konzistentné s OIDC flow. |

---

## 2) CSRF (Spring Security)

| Položka | DEV | PROD | Prečo |
|---|---|---|---|
| CSRF zapnuté | ✅ | ✅ | Pri session cookies je CSRF ochrana nutná. |
| Ignorovať OAuth callbacky (`/oauth2/**`, `/login/oauth2/**`) | ✅ | ✅ | Súčasť OIDC flow. |
| Ignorovať `/logout` | ❌ | ❌ | Inak “logout CSRF” (nútiteľné odhlásenie). |
| FE posiela `X-XSRF-TOKEN` | ✅ | ✅ | Na POST/PUT/DELETE (a aj logout). |

---

## 3) CORS

| Položka | DEV | PROD | Prečo |
|---|---|---|---|
| `allowedOrigins` | ✅ `http://localhost:3000` | ✅ konkrétna FE doména | Pri cookies nemôže byť `*`. |
| `allowCredentials` | ✅ `true` | ✅ `true` | Potrebné pre session cookie. |
| `allowedHeaders` | ✅ + `X-XSRF-TOKEN` | ✅ + `X-XSRF-TOKEN` | CSRF header musí prejsť. |
| `allowedMethods` | ✅ podľa potreby | ✅ podľa potreby | Least privilege. |

---

## 4) CSP (Content-Security-Policy)

| Direktíva | DEV | PROD | Prečo |
|---|---|---|---|
| `default-src` | `'self'` | `'self'` | Základný “deny by default” prístup. |
| `script-src` | často `'unsafe-inline'` kvôli HMR | ✅ bez `unsafe-inline` | Kľúčové proti XSS. |
| `style-src` | často `'unsafe-inline'` | ✅ bez `unsafe-inline` | Znižuje riziko injection. |
| `connect-src` | + `ws://localhost:3000` | len potrebné domény | HMR websocket iba v DEV. |
| `frame-ancestors` | `'none'` | `'none'` | Anti-clickjacking. |
| `object-src` | voliteľné | ✅ `'none'` | Zakáže pluginy/objekty. |
| `base-uri` | voliteľné | ✅ `'self'` | Bráni útokom cez `<base>`. |

---

## 5) HSTS (Strict-Transport-Security)

| Položka | DEV | PROD | Prečo |
|---|---|---|---|
| HSTS | ❌ | ✅ (ak HTTPS) | Vynúti HTTPS, bráni downgrade. |
| `max-age` | - | napr. `31536000` | Typicky 1 rok. |
| `includeSubDomains` | - | podľa potreby | Len ak všetky subdomény sú HTTPS. |

---

# Praktické debug tipy

## Ako uvidieť redirect chain
- Browser DevTools → **Network**
- zapnúť **Preserve log**
- sledovať `302`:
  - `/oauth2/authorization/keycloak`
  - Keycloak `/auth`
  - `/login/oauth2/code/keycloak`
  - redirect späť na FE

## Ako skontrolovať cookies
- DevTools → Application/Storage → Cookies (pre `localhost:8080`)
- uvidíš:
  - `JSESSIONID` (HttpOnly)
  - `XSRF-TOKEN` (nie HttpOnly)

---

# Produkčné minimum (tl;dr)

1. ✅ HTTPS všade (alebo aspoň na edge + správne proxy nastavenia)
2. ✅ `server.servlet.session.cookie.secure=true`
3. ✅ CSP v PROD bez `unsafe-inline`
4. ✅ HSTS zapnúť (iba na HTTPS)
5. ✅ CORS len na FE doménu + `allowCredentials=true`
6. ✅ CSRF zapnuté a `/logout` CSRF-protected

---
## Troubleshooting

### 403 na POST /logout
- FE musí posielať `credentials: "include"`
- FE musí posielať `X-XSRF-TOKEN` header (z cookie `XSRF-TOKEN`)
- CORS musí povoľovať `X-XSRF-TOKEN`

### Login redirect loop
Najčastejšie príčiny:
- zlá `KEYCLOAK_ISSUER_URI`
- zlá `redirect_uri` v Keycloak klientovi
- cookie sa neuloží/neposiela (napr. Secure cookie na HTTP, proxy nastavenie)

### FE nevie načítať usera (/api/me vracia 401)
- request musí byť s `credentials: "include"`
- CORS origin musí byť presne FE URL (nie `*`)

---
