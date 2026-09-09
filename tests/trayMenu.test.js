'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { trayGroups } = require('../src/main/trayMenu');

test('trayGroups: hand-added first, then each subscription that has servers, orphans last, capped', () => {
  const servers = [
    { id: 'a1', name: 'A1', subId: 'A' }, { id: 'm1', name: 'M1' }, { id: 'b1', name: 'B1', subId: 'B' },
    { id: 'a2', name: 'A2', subId: 'A' }, { id: 'x', name: 'X', subId: 'gone' }, { id: 'm2', address: 'h.example' }
  ];
  const subs = [{ id: 'A', name: 'Sub A' }, { id: 'B', name: 'Sub B' }, { id: 'C', name: 'Empty' }];
  assert.deepEqual(trayGroups(servers, subs), [
    { label: '', items: [{ id: 'm1', name: 'M1' }, { id: 'm2', name: 'h.example' }] },
    { label: 'Sub A', items: [{ id: 'a1', name: 'A1' }, { id: 'a2', name: 'A2' }] },
    { label: 'Sub B', items: [{ id: 'b1', name: 'B1' }] },
    { label: '?', items: [{ id: 'x', name: 'X' }] }
  ]);
  assert.deepEqual(trayGroups(servers, subs, 1).map(g => g.items.length), [1, 1, 1, 1], 'capped per group');
  assert.deepEqual(trayGroups([], subs), []);
  assert.deepEqual(trayGroups(null, null), []);
});
