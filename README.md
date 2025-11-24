# Ammonite Authentication

An Express middleware that authenticates requests by calling a remote userinfo endpoint with a bearer token. It caches user objects, enforces scopes, and surfaces sensible HTTP errors for callers.

## Installation

```bash
npm install ammonite-authentication
```

## Usage

```js
import express from 'express';
import Authentication from 'ammonite-authentication';

const auth = new Authentication('https://auth.example.com/userinfo');

const app = express();

app.get(
  '/protected',
  auth.middleware(['read']),
  (req, res) => res.json({ user: req.user })
);

app.listen(3000);
```

### Constructor

```js
new Authentication(getUserURL, options?)
```

- `getUserURL` (string, required): URL of your userinfo endpoint. The middleware will call this with `Authorization: Bearer <token>`.
- `options` (object, optional):
  - `cacheTime` (ms): How long to keep a user in the in-memory cache. Default: `60000`.
  - `requestTimeout` (ms): Axios timeout for the userinfo call. Default: `5000`.

### Middleware

```js
auth.middleware(requiredScopes?)
```

- `requiredScopes` can be `string | string[] | undefined`.
  - If omitted, only authentication is enforced.
  - If provided, the user must have all listed scopes unless they include `all`.
- On success, `req.user` is set to the user object returned by your userinfo endpoint, with:
  - `uid`: alias of `id`
  - `access_token`: the bearer token used
  - `cached`: `false` on fresh fetch, `true` on cache hits

### Error Handling

- Missing/invalid token → `401` with `WWW-Authenticate: Bearer`.
- Upstream 4xx/5xx statuses are propagated to the client.
- Network/timeouts → `502`.
- Missing scopes → `403` with message `missing scope <scope>`.

### Token Extraction

- Supports `Authorization: Bearer <token>` and `Authorization: Basic <base64 user:password>` (extracts the password).
- Scheme matching is case-sensitive (`Bearer`/`Basic`).

### Cache Management

- In-memory per-instance cache keyed by access token.
- Call `auth.close()` during shutdown to clear timers and cached entries.

## Testing

```bash
npm test
```

Mocha tests spin up a local Express app and exercise authentication, authorization, caching, and error paths.
