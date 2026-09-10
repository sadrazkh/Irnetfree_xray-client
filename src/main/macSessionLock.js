'use strict';
// Shared across both backends. A pending administrator prompt must not be
// mistaken for a crashed session by a second Connect or a backend switch.
module.exports = new Map();
