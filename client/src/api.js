import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token -------------------------------------------------------
// Every state-changing request must echo a secret CSRF token in the
// `x-csrf-token` header. Only our own origin can read that token (from
// GET /api/csrf-token), so a forged request from another site can't include it.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists and are exempt on the server.
const EXEMPT_PATHS = ['/auth/login', '/auth/register']
// These routes change the session, which invalidates any token bound to the old one.
const SESSION_CHANGING_PATHS = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pendingToken = null

function matches(url, paths) {
  return paths.some(p => (url || '').includes(p))
}

export function clearCsrfToken() {
  csrfToken = null
  pendingToken = null
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!pendingToken) {
    pendingToken = api.get('/csrf-token')
      .then(res => {
        csrfToken = res.data.csrfToken
        return csrfToken
      })
      .finally(() => { pendingToken = null })
  }
  return pendingToken
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method) && !matches(config.url, EXEMPT_PATHS)) {
    const token = await getCsrfToken()
    config.headers.set('x-csrf-token', token)
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    if (matches(res.config.url, SESSION_CHANGING_PATHS)) clearCsrfToken()
    return res
  },
  async (error) => {
    const { config, response } = error
    // A stale token (e.g. the session cookie was refreshed) — fetch a new one and retry once.
    if (response?.status === 403 && config && !config._csrfRetried && !matches(config.url, EXEMPT_PATHS)) {
      clearCsrfToken()
      config._csrfRetried = true
      return api(config)
    }
    return Promise.reject(error)
  }
)
