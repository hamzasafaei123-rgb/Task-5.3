import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the signed double-submit-cookie pattern (csrf-csrf).
//
// How it works:
//   1. The client calls GET /api/csrf-token. The server generates a token that is
//      an HMAC over (a random value + the caller's session identifier), signed with
//      CSRF_SECRET. It sets that value in a cookie and also returns it in the JSON body.
//   2. On every state-changing request the client echoes the token back in the
//      `x-csrf-token` header. The middleware checks that the header matches the cookie
//      AND that the HMAC is valid for *this* session.
//
// Why the attacker can't do this: a cross-site page can make the browser send our
// cookies, but it cannot read our cookies or responses (same-origin policy and CORS),
// so it never learns the token. It also cannot add a custom header to a plain HTML
// <form> post, and a cross-origin fetch carrying a custom header is blocked by the
// CORS preflight. A token minted for a different session fails the HMAC check.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so a missing/rotated env var is picked up at request time.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the logged-in session (the JWT cookie). When the session
  // changes (login / register / logout) old tokens stop being valid.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // The library default "__Host-" prefix requires HTTPS; we run on plain http locally.
  cookieName: process.env.NODE_ENV === 'production' ? '__Host-x-csrf-token' : 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  },
  // "Safe" methods don't change state and are never protected.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Pre-auth routes run before any session exists, so there is nothing to forge yet.
  skipCsrfProtection: (req) =>
    req.path === '/api/auth/login' || req.path === '/api/auth/register',
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

// GET /api/csrf-token — hand the caller a fresh token for their current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
