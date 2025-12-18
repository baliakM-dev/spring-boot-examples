# BFF + OIDC (Keycloak) + Session Cookies — Login/Logout Flow (Spring Boot 4 + Vue)

Tento projekt používa architektúru **BFF (Backend For Frontend)** so **server-side session** a **OIDC loginom cez Keycloak**.  
Frontend (Vue) **nepoužíva JWT tokeny** na autentifikáciu — autentifikácia je riešená cez **HttpOnly session cookie**.

---

## Komponenty a porty

- **Frontend (Vue)**: `http://localhost:3000`
- **Backend / BFF (Spring Boot 4.0.0)**: `http://localhost:8080`
- **Keycloak (OIDC Provider)**: `http://localhost:8081`

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

## Login flow — “klasický” diagram (Mermaid)

> Ak tvoj renderer nepodporuje Mermaid, nižšie je aj textová verzia.

mermaid sequenceDiagram autonumber participant U as User/Browser participant FE as Frontend (3000) participant BFF as Backend/BFF (8080) participant KC as Keycloak (8081)
U->>FE: GET [http://localhost:3000/](http://localhost:3000/) FE-->>U: 200 HTML/JS
FE->>BFF: GET [http://localhost:8080/api/me](http://localhost:8080/api/me) (credentials: include) BFF-->>FE: 401/302 -> /oauth2/authorization/keycloak
U->>BFF: GET /oauth2/authorization/keycloak Note over BFF: Create state+nonce\nStore in session BFF-->>U: 302 Location: Keycloak /auth?...state&nonce
U->>KC: GET /auth?...client_id=bff-client&redirect_uri=...&state&nonce KC-->>U: Login UI / SSO Note over KC: User authenticates KC-->>U: 302 Location: [http://localhost:8080/login/oauth2/code/keycloak?code&state](http://localhost:8080/login/oauth2/code/keycloak?code&state)
U->>BFF: GET /login/oauth2/code/keycloak?code&state (Cookie: JSESSIONID) Note over BFF: Validate state\nExchange code -> tokens (server-to-server) BFF->>KC: POST /token (code, client_id, client_secret) KC-->>BFF: 200 access_token/id_token
Note over BFF: Create authenticated session\nMap claim roles -> ROLE_ADMIN/ROLE_HR BFF-->>U: 302 Location: [http://localhost:3000/\nSet-Cookie](http://localhost:3000/%5CnSet-Cookie): JSESSIONID (HttpOnly)\nSet-Cookie: XSRF-TOKEN
FE->>BFF: GET /api/me (credentials: include, Cookie: JSESSIONID) BFF-->>FE: 200 { username, email, roles:[ADMIN,HR] }
