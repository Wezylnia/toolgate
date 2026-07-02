export const defaultSensitiveKeys = [
  "token",
  "apiKey",
  "apikey",
  "secret",
  "password",
  "authorization",
  "auth",
  "clientSecret",
  "connectionString"
];

export const defaultSensitivePatterns = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{10,}\b/gi,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  /\b(password|token|api[_-]?key|authorization)\s*[:=]\s*["']?[^"'\s,}]+/gi
];
