// 15-errors.js — typed error classes. Callers can `instanceof`-branch on
// these in the SW; the RPC layer serialises a `code` field to the page.

class GplaydlError extends Error {
  /**
   * @param {string} message
   * @param {string} code  One of: AUTH | NETWORK | PLAY_API | PROTO | VALIDATION
   * @param {object} [extra]  Additional structured fields (e.g. http status).
   */
  constructor(message, code, extra) {
    super(message);
    this.name = 'GplaydlError';
    this.code = code;
    if (extra) Object.assign(this, extra);
  }
}

class AuthError       extends GplaydlError { constructor(m, extra)         { super(m, 'AUTH', extra);       this.name = 'AuthError'; } }
class NetworkError    extends GplaydlError { constructor(m, status)        { super(m, 'NETWORK', { status }); this.name = 'NetworkError'; } }
class PlayApiError    extends GplaydlError { constructor(m, status)        { super(m, 'PLAY_API', { status }); this.name = 'PlayApiError'; } }
class ProtoError      extends GplaydlError { constructor(m, extra)         { super(m, 'PROTO', extra);      this.name = 'ProtoError'; } }
class ValidationError extends GplaydlError { constructor(m, extra)         { super(m, 'VALIDATION', extra); this.name = 'ValidationError'; } }
