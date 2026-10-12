'use strict';
/**
 * Android's copy of the server editor's field table is generated from the
 * desktop's (scripts/gen-android-server-fields.js): the checked-in Kotlin must
 * be exactly what the generator writes now, so the two tables cannot drift.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { render, OUT } = require('../scripts/gen-android-server-fields');

test('ServerFieldsTable.kt is what scripts/gen-android-server-fields.js writes from serverFields.js and i18n.js', () => {
  const now = fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n');
  assert.equal(now, render(), 'stale: run node scripts/gen-android-server-fields.js');
});
