'use strict';
/**
 * The device token that pairs a router with the relay: 32 random bytes as
 * base64url (43 characters, no padding). Minted by the relay's "Add router",
 * shown once, kept as its SHA-256 only; typed into LuCI on the router and
 * kept there write-only. One validator for both ends (the relay's Dockerfile
 * copies this file beside ws.js and frames.js).
 */
const crypto = require('crypto');

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

const mintToken = () => crypto.randomBytes(32).toString('base64url');
const isToken = (s) => typeof s === 'string' && TOKEN_RE.test(s);
const hashToken = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

module.exports = { mintToken, isToken, hashToken, TOKEN_RE };
