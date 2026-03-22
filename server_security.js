/**
 * ThreatIntel Platform — Security Utilities
 * XSS, SQL-injection, CSRF, header hardening.
 * Zero external dependencies.
 */

'use strict';
const crypto = require('crypto');

// ── Input sanitization ──────────────────────────────────────────

/**
 * Strip all HTML tags and dangerous characters from a string.
 * Safe for inserting into JSON or displaying as text.
 */
function sanitizeText(input, maxLength = 2000) {
  if (typeof input !== 'string') return '';
  return input
    .slice(0, maxLength)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;')
    .replace(/\//g, '&#x2F;')
    // Remove null bytes and control characters except \n \r \t
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * Validate username: alphanumeric + underscore + hyphen, 3–30 chars.
 * No injection possible — no special characters allowed at all.
 */
function validateUsername(u) {
  if (typeof u !== 'string') return false;
  return /^[a-zA-Z0-9_-]{3,30}$/.test(u);
}

/**
 * Validate password strength: 8+ chars, at least one number.
 */
function validatePassword(p) {
  if (typeof p !== 'string') return false;
  if (p.length < 8 || p.length > 128) return false;
  return /\d/.test(p); // at least one digit
}

/**
 * Validate IOC — must match known safe patterns before any API call.
 */
function validateIOC(v) {
  if (typeof v !== 'string') return false;
  const t = v.trim();
  if (t.length === 0 || t.length > 2048) return false;
  // IP
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) {
    return t.split('.').every(n => parseInt(n) <= 255);
  }
  // URL — must start with http(s)://
  if (/^https?:\/\//i.test(t)) return t.length <= 2048;
  // Hash
  if (/^[a-fA-F0-9]{32,64}$/.test(t)) return true;
  // Domain — no special chars that could cause injection
  if (/^(?!https?:\/\/)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(t)) return true;
  return false;
}

/**
 * Sanitize a comment — allow basic text, strip HTML.
 * Returns null if invalid.
 */
function validateComment(text) {
  if (typeof text !== 'string') return null;
  const clean = text.trim();
  if (clean.length === 0) return null;
  if (clean.length > 2000) return null;
  // Strip any HTML tags
  return clean.replace(/<[^>]*>/g, '').trim();
}

// ── CSRF tokens ─────────────────────────────────────────────────
const csrfTokens = new Map(); // In production use Redis; Map is fine for single-process

function generateCSRFToken(sessionToken) {
  const token = crypto.randomBytes(32).toString('hex');
  csrfTokens.set(token, { sessionToken, expiresAt: Date.now() + 3600000 });
  return token;
}

function validateCSRFToken(token, sessionToken) {
  const rec = csrfTokens.get(token);
  if (!rec) return false;
  if (Date.now() > rec.expiresAt) { csrfTokens.delete(token); return false; }
  return rec.sessionToken === sessionToken;
}

// Clean expired CSRF tokens every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, rec] of csrfTokens.entries()) {
    if (now > rec.expiresAt) csrfTokens.delete(token);
  }
}, 600000);

// ── Security headers ────────────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',   'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('X-XSS-Protection',          '1; mode=block');
  res.setHeader('Referrer-Policy',            'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; " +
    "font-src 'self' https://fonts.gstatic.com data:; " +
    "img-src 'self' data:; " +
    "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; " +
    "frame-ancestors 'none';"
  );
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
}

// ── Rate limiter (in-memory, per IP) ────────────────────────────
const rateLimitStore = new Map();

/**
 * @param {string} ip
 * @param {string} route — different limits per route
 * @param {number} maxReqs — max requests
 * @param {number} windowMs — sliding window in ms
 */
function rateLimit(ip, route, maxReqs, windowMs) {
  const key = `${ip}:${route}`;
  const now = Date.now();
  let rec   = rateLimitStore.get(key);
  if (!rec) { rec = { requests: [], blocked: false }; rateLimitStore.set(key, rec); }
  rec.requests = rec.requests.filter(t => now - t < windowMs);
  if (rec.requests.length >= maxReqs) {
    return { allowed: false, retryAfter: Math.ceil((rec.requests[0] + windowMs - now) / 1000) };
  }
  rec.requests.push(now);
  return { allowed: true };
}

// Clean rate limit store every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, rec] of rateLimitStore.entries()) {
    rec.requests = rec.requests.filter(t => now - t < 60 * 60 * 1000);
    if (rec.requests.length === 0) rateLimitStore.delete(key);
  }
}, 300000);

module.exports = {
  sanitizeText, validateUsername, validatePassword,
  validateIOC, validateComment,
  generateCSRFToken, validateCSRFToken,
  setSecurityHeaders, rateLimit,
};
