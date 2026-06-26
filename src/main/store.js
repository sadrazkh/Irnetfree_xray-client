'use strict';
/** Minimal JSON store persisted to disk (no external deps). */

const fs = require('fs');
const path = require('path');

class Store {
  constructor(filePath, defaults = {}) {
    this.filePath = filePath;
    this.data = Object.assign({}, defaults);
    this.load(defaults);
  }
  load(defaults) {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        this.data = Object.assign({}, defaults, raw);
      }
    } catch { /* keep defaults on corrupt file */ }
  }
  get(key, fallback) {
    return key in this.data ? this.data[key] : fallback;
  }
  set(key, value) {
    this.data[key] = value;
    this.save();
  }
  assign(obj) {
    Object.assign(this.data, obj);
    this.save();
  }
  all() { return this.data; }
  save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (e) { /* ignore */ }
  }
}

module.exports = { Store };
