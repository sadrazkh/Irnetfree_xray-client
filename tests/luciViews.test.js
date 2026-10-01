'use strict';
/**
 * The LuCI pages — openwrt/files/luci/view/{overview,settings,remote,log}.js
 * and irnetfree-common.js — loaded the way LuCI's own loader loads a class:
 * the 'require …' directives read off the top of the file, then the source
 * compiled as `function (window, document, L, <one argument per require>)` and
 * called with the required modules. Here those modules are a small fake LuCI:
 * a DOM of plain objects, E()/dom with LuCI's semantics (a bare string child is
 * innerHTML, a null in a children array renders as the text "null" — both
 * refused here), rpc.declare answering from a table with the same `expect`
 * rule, and form classes that record what a page declares and store values the
 * way CBIJSONConfig does. What cannot run here — the real LuCI in a browser —
 * is the QEMU job's part.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DIR = path.join(__dirname, '..', 'openwrt', 'files', 'luci');
const COMMON = path.join(DIR, 'irnetfree-common.js');
const VIEWS = ['overview', 'settings', 'remote', 'log'];
const viewFile = (v) => path.join(DIR, 'view', v + '.js');
const read = (f) => fs.readFileSync(f, 'utf8');

/* ------------------------------ LuCI's loader ------------------------------ */

/** LuCI's directive scan (luci.js require()): quoted strings at the top of the file until the first that is not one. */
function directives(source) {
  const requirematch = /^require[ \t]+(\S+)(?:[ \t]+as[ \t]+([a-zA-Z_]\S*))?$/;
  const strictmatch = /^use[ \t]+strict$/;
  const out = [];
  for (let i = 0, off = -1, prev = -1, quote = -1, comment = -1, esc = false; i < source.length; i++) {
    const chr = source.charCodeAt(i);
    if (esc) esc = false;
    else if (comment !== -1) { if ((comment === 47 && chr === 10) || (comment === 42 && prev === 42 && chr === 47)) comment = -1; }
    else if ((chr === 42 || chr === 47) && prev === 47) comment = chr;
    else if (chr === 92) esc = true;
    else if (chr === quote) {
      const s = source.substring(off, i);
      const m = requirematch.exec(s);
      if (m) out.push({ dep: m[1], as: m[2] || m[1].replace(/[^a-zA-Z0-9_]/g, '_') });
      else if (!strictmatch.exec(s)) break;
      off = -1; quote = -1;
    }
    else if (quote === -1 && (chr === 34 || chr === 39)) { off = i + 1; quote = chr; }
    prev = chr;
  }
  return out;
}

/** Compile a class file as LuCI does and call its factory with the modules it requires. */
function loadClass(file, modules, env) {
  const source = read(file);
  const deps = directives(source);
  const factory = new Function('window', 'document', 'L', ...deps.map((d) => d.as), source);   // eslint-disable-line no-new-func
  const args = deps.map((d) => {
    if (!(d.dep in modules)) throw new Error(`${path.basename(file)} requires ${d.dep}, which the fake LuCI does not have`);
    return modules[d.dep];
  });
  return factory.apply(factory, [env.window, env.document, env.L, ...args]);
}

/* ------------------------------ a DOM of plain objects ------------------------------ */

class FakeText {
  constructor(data) { this.nodeType = 3; this.data = data; this.parentNode = null; }
  get textContent() { return this.data; }
}
class FakeNode {
  constructor(tag) {
    this.nodeType = tag === '#fragment' ? 11 : 1;
    this.tagName = String(tag).toUpperCase();
    this.attributes = {};
    this.childNodes = [];
    this.parentNode = null;
    this.listeners = {};
    this.style = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.scrollTop = 0;
    this.scrollHeight = 100;
    const cls = new Set();
    this.classList = {
      add: (...c) => c.forEach((x) => cls.add(x)), remove: (...c) => c.forEach((x) => cls.delete(x)),
      contains: (x) => cls.has(x), toggle: (x, on) => ((on === undefined ? !cls.has(x) : on) ? cls.add(x) : cls.delete(x))
    };
  }
  appendChild(n) {
    if (n.nodeType === 11) { for (const c of [...n.childNodes]) this.appendChild(c); return n; }
    if (n.parentNode) n.parentNode.removeChild(n);
    this.childNodes.push(n);
    n.parentNode = this;
    return n;
  }
  removeChild(n) {
    const i = this.childNodes.indexOf(n);
    if (i >= 0) this.childNodes.splice(i, 1);
    n.parentNode = null;
    return n;
  }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  setAttribute(k, v) { this.attributes[k] = String(v); if (k === 'value') this.value = String(v); if (k === 'class') String(v).split(/\s+/).filter(Boolean).forEach((c) => this.classList.add(c)); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k); }
  removeAttribute(k) { delete this.attributes[k]; }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    if (v != null && v !== '') this.appendChild(new FakeText(String(v)));
  }
  set innerHTML(v) { throw new Error(`innerHTML: a string went into the DOM as HTML (${JSON.stringify(String(v).slice(0, 60))}) — pass it inside an array, as a text node`); }
  querySelectorAll() { return []; }
  querySelector() { return null; }
  focus() {} blur() {} select() {}
  /* test helpers */
  all(pred, out = []) { for (const c of this.childNodes) { if (c.nodeType === 1) { if (pred(c)) out.push(c); c.all(pred, out); } } return out; }
  byTag(tag) { return this.all((n) => n.tagName === tag.toUpperCase()); }
  buttons() { return this.byTag('button'); }
  button(text) { const b = this.buttons().find((x) => x.textContent === text); assert.ok(b, `no button "${text}" in: ${this.textContent}`); return b; }
  fire(ev, event) { return (this.listeners[ev] || []).map((fn) => fn(event || { currentTarget: this, target: this })); }
}
const isNode = (x) => x != null && typeof x === 'object' && 'nodeType' in x;

/* LuCI's DOM.append / DOM.content / DOM.create, with its two traps turned into errors */
function append(node, children) {
  if (Array.isArray(children)) {
    for (const c of children) {
      if (isNode(c)) node.appendChild(c);
      else if (c === null || c === undefined) throw new Error('a null/undefined item in a children array: LuCI renders it as the text "null"');
      else node.appendChild(new FakeText('' + c));
    }
    return node.lastChild;
  }
  if (typeof children === 'function') return append(node, children(node));
  if (isNode(children)) return node.appendChild(children);
  if (children !== null && children !== undefined) node.innerHTML = '' + children;
  return null;
}
function E(html, attrs, data) {
  if (isNode(attrs)) throw new Error('E(tag, node): LuCI takes a node there as the attribute object — pass [node]');
  if (!(attrs instanceof Object) || Array.isArray(attrs)) { data = attrs; attrs = null; }
  let elem;
  if (Array.isArray(html)) { elem = new FakeNode('#fragment'); for (const h of html) elem.appendChild(E(h)); }
  else if (isNode(html)) elem = html;
  else if (String(html).charCodeAt(0) === 60) throw new Error('E() with markup');
  else elem = new FakeNode(html);
  for (const k in (attrs || {})) {
    if (!Object.prototype.hasOwnProperty.call(attrs, k) || attrs[k] == null) continue;
    const v = attrs[k];
    if (typeof v === 'function') elem.addEventListener(k, v);
    else if (typeof v === 'object') elem.setAttribute(k, JSON.stringify(v));
    else elem.setAttribute(k, v);
  }
  append(elem, data);
  return elem;
}
global.E = E;   // LuCI's E is a global the pages call by name

/* ------------------------------ the rest of the fake LuCI ------------------------------ */

function makeClass(proto, Base) {
  function C() { if (typeof this.__init__ === 'function') this.__init__.apply(this, arguments); }
  C.prototype = Object.assign(Object.create(Base ? Base.prototype : Object.prototype), proto);
  C.extend = (p) => makeClass(p, C);
  return C;
}

/** CBIJSONConfig's get/set: scalars come back as strings, arrays as they are, a missing option as null. */
class JSONData {
  constructor(data) { this.data = {}; for (const k of Object.keys(data)) this.data[k] = Object.assign({}, data[k]); }
  get(config, section, option) {
    if (section == null) return null;
    if (option == null) return this.data[section];
    if (!Object.prototype.hasOwnProperty.call(this.data, section)) return null;
    const v = this.data[section][option];
    if (Array.isArray(v)) return v;
    return v != null ? String(v) : null;
  }
  set(config, section, option, value) {
    if (section == null || option == null || option.charAt(0) === '.' || !this.data[section]) return;
    if (value == null) delete this.data[section][option];
    else this.data[section][option] = Array.isArray(value) ? value : String(value);
  }
  unset(config, section, option) { return this.set(config, section, option, null); }
}

function fakeForm(env) {
  const maps = [];
  class Opt {
    constructor(map, section, option, title, description) {
      Object.assign(this, { map, section, option, title, description, rmempty: true, optional: false, default: null, datatype: null, keylist: [], vallist: [] });
      this.formValue = undefined;   // set by a test: what the user typed or ticked
    }
    value(key, label) { this.keylist.push(String(key)); this.vallist.push(String(label != null ? label : key)); }
    cfgvalue(sid) { return this.map.data.get(this.map.config, sid, this.option); }
    parse(sid) {
      if (this.formValue === undefined) return;
      const v = this.formValue;
      if (this.datatype === 'macaddr' && Array.isArray(v)) for (const x of v) if (!/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(x)) throw new TypeError(`Option "${this.title}" contains an invalid input value.`);
      if (typeof this.validate === 'function') {
        const ok = this.validate(sid, v);
        if (ok !== true) throw new TypeError(`Option "${this.title}" contains an invalid input value. ${ok}`);
      }
      if (v == null || v === '' || (Array.isArray(v) && !v.length)) { if (this.rmempty || this.optional) this.map.data.unset(this.map.config, sid, this.option); else throw new TypeError('must not be empty'); }
      else this.map.data.set(this.map.config, sid, this.option, v);
    }
  }
  class Flag extends Opt {
    constructor(...a) { super(...a); this.enabled = '1'; this.disabled = '0'; this.default = '0'; }
    parse(sid) {
      if (this.formValue === undefined) return;
      const v = this.formValue ? this.enabled : this.disabled;
      if (v === this.default && (this.optional || this.rmempty)) this.map.data.unset(this.map.config, sid, this.option);
      else this.map.data.set(this.map.config, sid, this.option, v);
    }
  }
  class Value extends Opt {}
  class DynamicList extends Opt {}
  class DummyValue extends Opt { parse() {} }
  for (const C of [Flag, Value, DynamicList, DummyValue]) C.isOption = true;
  class NamedSection {
    constructor(map, sectionId, type, title, description) { Object.assign(this, { map, section: sectionId, sectiontype: type, title, description, options: [] }); }
    option(cls, ...a) {
      if (!cls || !cls.isOption) throw new TypeError('Class must be a descendent of CBIAbstractValue');
      const o = new cls(this.map, this, ...a);
      this.options.push(o);
      return o;
    }
  }
  NamedSection.isSection = true;
  class Map {
    constructor(config, title, description) {
      Object.assign(this, { config, title, description, sections: [], renders: 0, saves: 0, resets: 0 });
      this.data = env.uciData;
      maps.push(this);
    }
    section(cls, ...a) {
      if (!cls || !cls.isSection) throw new TypeError('Class must be a descendent of CBIAbstractSection');
      const s = new cls(this, ...a);
      this.sections.push(s);
      return s;
    }
    option(sectionId, name) { return this.sections.find((s) => s.section === sectionId).options.find((o) => o.option === name); }
    render() {
      this.renders++;
      const root = E('div', { 'class': 'cbi-map', 'data-config': this.config });
      root.map = this;
      for (const s of this.sections) for (const o of s.options) {
        // a page's own widget runs here, as LuCI would run it
        if (Object.prototype.hasOwnProperty.call(o, 'renderWidget')) {
          const w = o.renderWidget(s.section, 0, o.cfgvalue(s.section));
          assert.ok(isNode(w), `${o.option}: renderWidget returned no node`);
          root.appendChild(E('div', { 'class': 'cbi-value', 'data-name': o.option }, [ w ]));
        }
      }
      return Promise.resolve(root);
    }
    save() {
      this.saves++;
      try { for (const s of this.sections) for (const o of s.options) o.parse(s.section); }
      catch (e) { env.ui.modals.push({ title: 'Save error', error: e.message }); return Promise.reject(e); }
      return this.render().then(() => undefined);
    }
    reset() { this.resets++; return this.render(); }
  }
  class JSONMap extends Map {
    constructor(data, title, description) { super('json', title, description); this.data = new JSONData(data); }
  }
  return { maps, module: { Map, JSONMap, NamedSection, Flag, Value, DynamicList, DummyValue } };
}

/** A fresh fake LuCI; `replies` answers the plugin's methods (method → reply or function(params)). */
function fakeLuci(opts = {}) {
  const env = { lang: opts.lang || 'en', calls: [], timers: [], replies: Object.assign({}, opts.replies) };
  env.document = {
    documentElement: { getAttribute: (k) => (k === 'lang' ? env.lang : null) },
    body: new FakeNode('body'),
    execCommand: (cmd) => (cmd === 'copy' ? env.execCopy !== false : false)
  };
  env.window = {
    location: { hostname: '192.168.1.1', reloads: 0, reload() { this.reloads++; } },
    setTimeout: (fn, ms) => { env.timers.push({ fn, ms }); return env.timers.length; },
    navigator: {},
    isSecureContext: false
  };
  env.L = {
    env: {},
    resolveDefault: (p, d) => Promise.resolve(p).catch(() => d),
    bind: (fn, self, ...a) => fn.bind(self, ...a),
    toArray: (v) => (v == null ? [] : Array.isArray(v) ? v : typeof v === 'object' ? [v] : String(v).trim() === '' ? [] : String(v).trim().split(/\s+/)),
    isObject: (v) => v != null && typeof v === 'object'
  };
  env.uciValues = { irnetfree: { main: { port: '6969', bind: '0.0.0.0', data_dir: '/etc/irnetfree' } } };
  env.uciChanges = {};
  env.uciData = {
    get: (c, s, o) => { const v = ((env.uciValues[c] || {})[s] || {})[o]; return v == null ? null : v; },
    set: (c, s, o, v) => { env.uciValues[c][s][o] = v; },
    unset: (c, s, o) => { delete env.uciValues[c][s][o]; }
  };
  env.ui = {
    notes: [], modals: [], applied: [],
    addNotification(title, children, ...classes) { const n = E('div', { 'class': 'alert-message ' + classes.join(' ') }); append(n, children); n.kind = classes.join(' '); env.ui.notes.push(n); return n; },
    showModal(title, children) { env.ui.modals.push({ title, node: E('div', {}, children) }); },
    hideModal() {},
    createHandlerFn(ctx, fn, ...bound) {
      if (typeof fn === 'string') fn = ctx[fn];
      if (typeof fn !== 'function') return null;
      return (...a) => fn.apply(ctx, bound.concat(a));
    },
    changes: { apply: (checked) => env.ui.applied.push(checked) }
  };
  const rpc = {
    declare(o) {
      return (...args) => {
        const params = {};
        (o.params || []).forEach((p, i) => { if (args[i] !== undefined) params[p] = args[i]; });
        env.calls.push({ object: o.object, method: o.method, params });
        let r = env.replies[o.method];
        if (typeof r === 'function') r = r(params);
        // rpc.js: with expect {'': {}}, anything that is not an object (an array too) becomes {}
        return Promise.resolve(r).then((v) => (o.expect && Object.prototype.hasOwnProperty.call(o.expect, '') && Object.prototype.toString.call(v) !== '[object Object]') ? {} : v);
      };
    }
  };
  env.poll = { added: [], add: (fn, interval) => { env.poll.added.push({ fn, interval }); return true; } };
  env.fsCalls = [];
  const fsMod = { read: (p) => { env.fsCalls.push(p); return (p === '/etc/irnetfree/token' && env.token != null) ? Promise.resolve(env.token) : Promise.reject(new Error('Permission denied')); } };
  env.token = opts.token === undefined ? 'abc123' : opts.token;
  const uci = {
    load: (c) => Promise.resolve([c]),
    get: (c, s, o) => env.uciData.get(c, s, o),
    changes: () => Promise.resolve(env.uciChanges)
  };
  const form = fakeForm(env);
  env.maps = form.maps;
  env.lastView = null;
  const view = { extend: (p) => { env.lastView = makeClass(p); env.lastView.isView = true; return env.lastView; } };
  const dom = { content: (n, c) => { while (n.firstChild) n.removeChild(n.firstChild); return append(n, c); }, append, elem: isNode };
  env.modules = { baseclass: { extend: (p) => makeClass(p) }, rpc, ui: env.ui, dom, poll: env.poll, fs: fsMod, uci, form: form.module, view };
  env.common = new (loadClass(COMMON, env.modules, env))();
  env.modules['irnetfree.common'] = env.common;
  return env;
}

/** Load a view, run its load() and render() like LuCI's View does; the page node and the instance. */
async function openView(name, env) {
  const C = loadClass(viewFile(name), env.modules, env);
  assert.equal(C, env.lastView, `${name}: the factory must return view.extend(…)`);
  const v = Object.create(C.prototype);
  const data = await v.load();
  const page = await v.render(data);
  assert.ok(isNode(page), `${name}: render() gave no DOM node`);
  return { v, page };
}
const flush = () => new Promise((r) => setImmediate(r));
const callsOf = (env, method) => env.calls.filter((c) => c.method === method);

/* ------------------------------ the replies of a healthy service ------------------------------ */

const STATUS = {
  state: 'connected', reason: null, cause: 'user', attempt: 0, retryInMs: null, since: Date.now() - 3725000,
  serverId: 's2', label: 'ci-upstream', engine: 'xray', tun: true,
  killSwitch: { enabled: false, armed: false, blocking: false },
  version: '1.16.0', traffic: { up: 2048, down: 5 * 1048576, upRate: 100, downRate: 2048 }, memAvailableKb: 200000
};
const CONFIGS = {
  selectedId: 's2', activeId: 's2',
  groups: [
    { id: 'sub-1', name: 'My provider', kind: 'subscription', items: [{ id: 's1', name: 'DE-1', proto: 'vless' }, { id: 's2', name: 'ci-upstream', proto: 'socks' }] },
    { id: 'manual', name: 'manual', kind: 'manual', items: [{ id: 'm1', name: '<img src=x onerror=alert(1)>', proto: 'vmess' }] },
    { id: 'chains', name: 'chains', kind: 'chains', items: [] }
  ]
};
const healthy = (extra) => Object.assign({
  status: () => Object.assign({}, STATUS, { since: Date.now() - 3725000 }), configs: CONFIGS, connect: { accepted: true }, disconnect: { accepted: true }, reconnect: { accepted: true },
  select: { ok: true }, test: { ok: true, ms: 123 }, subs_update: { accepted: true },
  settings_get: { autoConnect: true, killSwitch: false, lanBlockQuic: true, lanBypassMacs: ['02:00:00:00:00:01'] },
  settings_set: (p) => ({ ok: true, settings: Object.assign({ autoConnect: true, killSwitch: false, lanBlockQuic: true, lanBypassMacs: ['02:00:00:00:00:01'] }, p) }),
  // the plugin wraps the service's array as {result: […]}
  devices: { result: [
    { mac: 'AA:BB:CC:DD:EE:FF', ip: '192.168.1.20', name: 'laptop', bypass: false },
    { mac: '02:00:00:00:00:01', ip: '192.168.1.21', name: '', bypass: true },
    { mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.1.20', name: 'laptop again', bypass: false },
    { mac: 'not-a-mac', ip: '192.168.1.22', name: 'junk' }
  ] },
  log: { lines: ['irnetfree: connected — ci-upstream', 'irnetfree: stats'] },
  diagnostics: { text: 'status: connected\nMemAvailable: 200000 kB' },
  remote_get: { relay: { enabled: true, relayUrl: 'https://relay.example.com', name: 'home', tokenSet: true }, cloudflared: { installed: false, enabled: false, tokenSet: false } },
  remote_status: { relay: { state: 'online', path: 'direct', since: Date.now() - 60000, lastError: null, relayHost: 'relay.example.com' }, cloudflared: { installed: false, running: false, lastLine: '' } },
  remote_set: { ok: true },
  cloudflared_install: { accepted: true },
  service: { ok: true }
}, extra);

/* ------------------------------ the files themselves ------------------------------ */

test('every page and the shared module parse as LuCI loads them and require only what LuCI has', () => {
  for (const f of [COMMON, ...VIEWS.map(viewFile)]) {
    const src = read(f);
    assert.match(src, /^'use strict';\n'require /, `${path.basename(f)}: 'use strict' and the requires first`);
    assert.ok(!src.includes('\r'), `${path.basename(f)}: LF only`);
    const deps = directives(src);
    assert.ok(deps.length, `${path.basename(f)}: no require directives found`);
    assert.doesNotThrow(() => new Function('window', 'document', 'L', ...deps.map((d) => d.as), src), `${path.basename(f)} does not compile`);   // eslint-disable-line no-new-func
    // ES5 for old browsers, like the rest of LuCI
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    assert.doesNotMatch(code, /=>/, `${path.basename(f)}: an arrow function`);
    assert.doesNotMatch(code, /^\s*(let|const|class)\s/m, `${path.basename(f)}: let/const/class`);
    assert.doesNotMatch(code, /`/, `${path.basename(f)}: a template string`);
  }
  for (const v of VIEWS) {
    const deps = directives(read(viewFile(v))).map((d) => d.dep + (d.as !== d.dep.replace(/[^a-zA-Z0-9_]/g, '_') ? ' as ' + d.as : ''));
    assert.ok(deps.includes('view'), `${v} requires view`);
    assert.ok(deps.includes('irnetfree.common as common'), `${v} requires irnetfree.common as common`);
  }
});

test('the shared module is a class LuCI can instantiate, with every call the facade has', () => {
  const env = fakeLuci();
  const c = env.common;
  for (const m of ['status', 'configs', 'connect', 'select', 'disconnect', 'reconnect', 'test', 'subsUpdate', 'settingsGet', 'settingsSet',
    'devices', 'log', 'diagnostics', 'remoteGet', 'remoteSet', 'remoteStatus', 'cloudflaredInstall', 'service', 't', 'badge']) {
    assert.equal(typeof c[m], 'function', m);
  }
});

test('the pages call only what the shared module has', () => {
  const env = fakeLuci();
  for (const v of VIEWS) {
    const used = new Set([...read(viewFile(v)).matchAll(/\bcommon\.([A-Za-z_$][\w$]*)/g)].map((m) => m[1]));
    assert.ok(used.size > 3, v);
    for (const name of used) assert.ok(name in env.common, `${v}.js calls common.${name}, which irnetfree-common.js does not have`);
  }
});

test('the calls go to luci.irnetfree with the parameter names the plugin declares', async () => {
  const env = fakeLuci({ replies: healthy() });
  const c = env.common;
  await c.connect('s1');
  await c.select('s2');
  await c.log(300);
  await c.settingsSet(undefined, true, undefined, ['aa:bb:cc:dd:ee:ff']);
  await c.remoteSet({ enabled: true }, undefined);
  await c.service('start');
  assert.deepEqual(env.calls.map((x) => [x.object, x.method, x.params]), [
    ['luci.irnetfree', 'connect', { id: 's1' }],
    ['luci.irnetfree', 'select', { id: 's2' }],
    ['luci.irnetfree', 'log', { lines: 300 }],
    ['luci.irnetfree', 'settings_set', { killSwitch: true, lanBypassMacs: ['aa:bb:cc:dd:ee:ff'] }],
    ['luci.irnetfree', 'remote_set', { relay: { enabled: true } }],
    ['luci.irnetfree', 'service', { action: 'start' }]
  ]);
  // and every method the shared module calls is one the plugin declares
  const plugin = read(path.join(__dirname, '..', 'openwrt', 'files', 'rpcd', 'luci.irnetfree'));
  const declared = JSON.parse(/cat <<'EOF'\n([\s\S]*?)\nEOF/.exec(plugin)[1]);
  const methods = [...read(COMMON).matchAll(/method: '([a-z_]+)'|call\('([a-z_]+)'/g)].map((m) => m[1] || m[2]);
  for (const m of methods) assert.ok(m in declared, `common.js calls ${m}, which the plugin does not declare`);
  assert.deepEqual([...new Set(methods)].sort(), Object.keys(declared).sort(), 'every declared method has a call');
});

/* ------------------------------ language ------------------------------ */

function stringsOf(file) {
  const src = read(file);
  const re = file === COMMON ? /(?:^|[^\w.$])t\(\s*'((?:[^'\\]|\\.)*)'/g : /\bcommon\.t\(\s*'((?:[^'\\]|\\.)*)'/g;
  return [...src.matchAll(re)].map((m) => m[1].replace(/\\(.)/g, '$1'));
}

test('Persian: every string the pages show has an entry, with the same %s count and Persian text', () => {
  const env = fakeLuci();
  const fa = env.common.dict;
  const used = new Set();
  for (const f of [COMMON, ...VIEWS.map(viewFile)]) {
    for (const s of stringsOf(f)) {
      used.add(s);
      assert.ok(Object.prototype.hasOwnProperty.call(fa, s), `${path.basename(f)}: no Persian for ${JSON.stringify(s)}`);
    }
    // a t() with anything but a literal first argument could not be checked here
    const src = read(f).replace(/function t\(en\)/, '');
    const re = f === COMMON ? /(?:^|[^\w.$])t\(\s*[^'\s)]/ : /\bcommon\.t\(\s*[^'\s)]/;
    assert.doesNotMatch(src, re, `${path.basename(f)}: t() with a non-literal string`);
  }
  for (const [en, p] of Object.entries(fa)) {
    assert.ok(used.has(en), `a Persian entry nothing uses: ${JSON.stringify(en)}`);
    assert.equal((p.match(/%s/g) || []).length, (en.match(/%s/g) || []).length, `%s count differs for ${JSON.stringify(en)}`);
    if (en !== 'VPN') assert.match(p, /[؀-ۿ]/, `not Persian: ${JSON.stringify(p)}`);
    assert.doesNotMatch(p + en, /[<>]/, 'form titles and descriptions are HTML in LuCI: no < or > in a string');
  }
  // an object literal with a key twice is a SyntaxError in strict ES5 (old browsers)
  const literal = /var FA = \{([\s\S]*?)\n\};/.exec(read(COMMON))[1];
  const keys = [...literal.matchAll(/^\t'((?:[^'\\]|\\.)*)':/gm)].map((m) => m[1]);
  assert.equal(keys.length, Object.keys(fa).length, 'every entry is one line');
  assert.equal(new Set(keys).size, keys.length, 'a key is in the dictionary twice');
});

test('t(): Persian when LuCI runs in fa (or fa-IR), English otherwise, %s filled in order', () => {
  const en = fakeLuci({ lang: 'en' }).common;
  assert.equal(en.t('Reconnecting… (attempt %s)', 2), 'Reconnecting… (attempt 2)');
  assert.equal(en.t('Not in the dictionary %s', 'x'), 'Not in the dictionary x');
  const fa = fakeLuci({ lang: 'fa' }).common;
  assert.equal(fa.t('Reconnecting… (attempt %s)', 2), 'اتصال مجدد… (تلاش 2)');
  assert.equal(fa.t('Connected'), 'متصل');
  assert.equal(fakeLuci({ lang: 'fa-IR' }).common.t('Disconnected'), 'قطع شده');
  assert.equal(fakeLuci({ lang: 'fr' }).common.t('Disconnected'), 'Disconnected');
});

/* ------------------------------ badge ------------------------------ */

test('badge(): each of the six states the service reports, with the attempt and the reason', () => {
  const b = fakeLuci().common.badge;
  assert.deepEqual(b('connected', 0, null), { text: 'Connected', tone: 'ok' });
  assert.deepEqual(b('connecting', 0, null), { text: 'Connecting…', tone: 'busy' });
  assert.deepEqual(b('reconnecting', 2, 'core exited'), { text: 'Reconnecting… (attempt 2)', tone: 'busy' });
  assert.deepEqual(b('reconnecting', 0, null), { text: 'Reconnecting…', tone: 'busy' });
  assert.deepEqual(b('waiting', 3, null), { text: 'Waiting for internet… (attempt 3)', tone: 'busy' });
  assert.deepEqual(b('waiting', null, null), { text: 'Waiting for internet…', tone: 'busy' });
  assert.deepEqual(b('disconnected', 0, null), { text: 'Disconnected', tone: 'off' });
  assert.deepEqual(b('error', 0, 'no route to the server'), { text: 'Error: no route to the server', tone: 'bad' });
  assert.deepEqual(b('error', 0, null), { text: 'Error', tone: 'bad' });
  assert.deepEqual(b('something new', 0, null), { text: 'Unknown', tone: 'off' });
  const fa = fakeLuci({ lang: 'fa' }).common.badge;
  assert.equal(fa('connected').text, 'متصل');
  assert.equal(fa('waiting', 4).text, 'منتظر اینترنت… (تلاش 4)');
  assert.equal(fa('error', 0, 'boom').text, 'خطا: boom');
});

test('the small helpers: errors in words, sizes, durations, MACs, what changed', () => {
  const c = fakeLuci().common;
  assert.equal(c.errorOf({ state: 'connected' }), null);
  assert.equal(c.errorOf({ error: 'not-running' }), 'The IRNetFree service is not running.');
  assert.equal(c.errorOf({ error: 'http 405' }), 'This IRNetFree service does not know this request yet — update IRNetFree.');
  assert.equal(c.errorOf({ error: 'http 502' }), 'The service answered with an error (HTTP 502).');
  assert.equal(c.errorOf({ error: 'unauthorized' }), 'The service refused the request: its token changed. Restart the service.');
  assert.equal(c.errorOf({ error: 'remote not available' }), 'Remote access is not part of this IRNetFree version.');
  assert.equal(c.errorOf({ error: 'bad MAC 11' }), 'Error: bad MAC 11');
  assert.equal(c.errorOf({}), 'No answer from the service.', '{} is what LuCI gives for a failed ubus call');
  assert.equal(c.errorOf(null), 'No answer from the service.');
  assert.equal(c.isDown({ error: 'not-running' }), true);
  assert.equal(c.isDown({ error: 'timeout' }), false);
  assert.deepEqual(c.list({ result: [1] }), [1]);
  assert.deepEqual(c.list({ error: 'x' }), []);
  assert.equal(c.duration(3725), '01:02:05');
  assert.equal(c.duration(90061), '1d 01:01:01');
  assert.equal(c.size(512), '512 B');
  assert.equal(c.size(1536), '1.50 KB');
  assert.equal(c.size(5 * 1048576), '5.00 MB');
  assert.equal(c.rate(2048), '2.00 KB/s');
  assert.equal(c.normMac(' AA-BB-CC-DD-EE-FF '), 'aa:bb:cc:dd:ee:ff');
  assert.equal(c.isMac('aa:bb:cc:dd:ee:f'), false);
  assert.deepEqual(c.changed({ a: true, l: ['x', 'y'] }, { a: true, l: ['y', 'x'] }), null, 'lists compare as sets');
  assert.deepEqual(c.changed({ a: true, l: [] }, { a: false, l: ['x'] }), { a: false, l: ['x'] });
  assert.equal(c.validRelayUrl('https://relay.example.com'), true);
  assert.equal(c.validRelayUrl('https://relay.example.com:8443/'), true);
  assert.equal(c.validRelayUrl('http://relay.example.com'), false);
  assert.equal(c.validRelayUrl('https://relay.example.com/x'), false);
  assert.equal(c.validRouterName('x'.repeat(40)), true);
  assert.equal(c.validRouterName('x'.repeat(41)), false);
  assert.equal(c.webUiUrl('192.168.1.1', '6969', 'a b'), 'http://192.168.1.1:6969/?token=a%20b');
  assert.equal(c.webUiUrl('192.168.1.1', '6969', ''), 'http://192.168.1.1:6969/');
  assert.equal(c.remoteLine(undefined), null);
  assert.equal(c.remoteLine({ relay: { state: 'error', lastError: 'dns' }, cloudflared: { installed: true, running: true } }),
    'Relay: offline — dns · Cloudflare Tunnel: running');
  assert.equal(c.relayText({ state: 'online', path: 'vpn' }), 'online through the VPN');
});

/* ------------------------------ Overview ------------------------------ */

test('Overview: the live state, the VPN switch on, the config, uptime, traffic, the picker grouped like the web UI', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v, page } = await openView('overview', env);
  const text = page.textContent;
  assert.match(text, /Connected/);
  assert.match(text, /Version 1\.16\.0/);
  assert.equal(v.el.vpn.checked, true);
  assert.equal(v.el.vpnText.textContent, 'On');
  assert.equal(v.el.config.textContent, 'ci-upstream (xray)');
  assert.match(v.el.uptime.textContent, /^01:02:0[5-7]$/, 'uptime from `since`');
  assert.equal(v.el.traffic.textContent, 'Download 5.00 MB (2.00 KB/s) · Upload 2.00 KB (100 B/s)');
  assert.equal(v.el.ks.textContent, 'Off');
  assert.equal(v.el.block.style.display, 'none');
  assert.equal(v.el.remoteRow.style.display, 'none', 'no remote line when the service reports none');
  // the picker: one <optgroup> per non-empty group, the active config marked, a hostile name as text
  const groups = v.el.picker.byTag('optgroup');
  assert.deepEqual(groups.map((g) => g.getAttribute('label')), ['My provider', 'Manual servers']);
  assert.deepEqual(v.el.picker.byTag('option').map((o) => [o.getAttribute('value'), o.textContent]), [
    ['s1', 'DE-1 · vless'], ['s2', '● ci-upstream · socks'], ['m1', '<img src=x onerror=alert(1)> · vmess']
  ]);
  assert.equal(v.el.picker.value, 's2');
  // polled: the status every 3 s, the uptime every second
  assert.deepEqual(env.poll.added.map((p) => p.interval), [3, 1]);
  // the web UI link: the token file and the uci port, as the old page built it
  const link = page.byTag('a').find((a) => a.textContent === 'Open full web UI');
  assert.equal(link.getAttribute('href'), 'http://192.168.1.1:6969/?token=abc123');
  assert.equal(link.getAttribute('target'), '_blank');
  assert.deepEqual(env.fsCalls, ['/etc/irnetfree/token']);
  // no Save / Save & Apply / Reset: everything here acts at once
  assert.equal(v.handleSave, null);
  assert.equal(v.handleSaveApply, null);
  assert.equal(v.handleReset, null);
});

test('Overview: the actions — switch, Connect, Reconnect, Test, Update subscriptions, picking a config', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v, page } = await openView('overview', env);
  env.calls.length = 0;

  await v.handleSwitch({ currentTarget: { checked: false } });
  assert.deepEqual(callsOf(env, 'disconnect').length, 1);
  v.el.picker.value = 's1';
  await v.handleSwitch({ currentTarget: { checked: true } });
  assert.deepEqual(callsOf(env, 'connect').map((c) => c.params), [{ id: 's1' }]);
  await page.button('Connect').fire('click')[0];
  assert.deepEqual(callsOf(env, 'connect').map((c) => c.params), [{ id: 's1' }, { id: 's1' }]);
  await page.button('Reconnect').fire('click')[0];
  assert.equal(callsOf(env, 'reconnect').length, 1);
  // every action is followed by a fresh status
  assert.ok(callsOf(env, 'status').length >= 4);

  await page.button('Test connection').fire('click')[0];
  assert.equal(v.el.result.textContent, 'Test: 123 ms');
  env.replies.test = { ok: false, error: 'timeout through the tunnel' };
  await v.handleTest();
  assert.equal(v.el.result.textContent, 'Test failed: timeout through the tunnel');
  env.replies.test = { error: 'not-running' };
  await v.handleTest();
  assert.equal(v.el.result.textContent, 'Test failed: The IRNetFree service is not running.');

  const due = v.cfgDue;
  await page.button('Update subscriptions').fire('click')[0];
  assert.equal(callsOf(env, 'subs_update').length, 1);
  assert.ok(v.cfgDue < due, 'the config list is re-read soon after');
  assert.match(env.ui.notes.pop().textContent, /Updating subscriptions/);

  v.el.picker.value = 'm1';
  await v.el.picker.fire('change')[0];
  assert.deepEqual(callsOf(env, 'select').map((c) => c.params), [{ id: 'm1' }]);

  // nothing picked and nothing selected: the switch does not turn on
  const empty = fakeLuci({ replies: healthy({ configs: { selectedId: null, activeId: null, groups: [] } }) });
  const o = await openView('overview', empty);
  empty.calls.length = 0;
  await o.v.handleSwitch({ currentTarget: { checked: true } });
  assert.equal(callsOf(empty, 'connect').length, 0);
  assert.equal(o.v.el.vpn.checked, false);
  assert.match(empty.ui.notes[0].textContent, /Choose a config first/);
  assert.match(o.page.textContent, /No configs yet/);
});

test('Overview: reconnecting, waiting, the kill switch blocking (and its Turn the VPN off), remote states', async () => {
  const env = fakeLuci({ replies: healthy({
    status: Object.assign({}, STATUS, { state: 'reconnecting', attempt: 2, since: null,
      killSwitch: { enabled: true, armed: true, blocking: true },
      remote: { relay: { state: 'online', path: 'direct' }, cloudflared: { installed: true, running: false } } })
  }) });
  const { v, page } = await openView('overview', env);
  assert.match(page.textContent, /Reconnecting… \(attempt 2\)/);
  assert.equal(v.el.vpn.checked, true, 'reconnecting is still "on"');
  assert.equal(v.el.uptime.textContent, '—');
  assert.equal(v.el.ks.textContent, 'On — blocking');
  assert.equal(v.el.block.style.display, '');
  assert.match(v.el.block.textContent, /LAN internet is blocked until the VPN is back/);
  assert.equal(v.el.remote.textContent, 'Relay: online (direct) · Cloudflare Tunnel: stopped');
  assert.equal(v.el.remoteRow.style.display, '');
  env.calls.length = 0;
  await v.el.block.button('Turn the VPN off').fire('click')[0];
  assert.equal(callsOf(env, 'disconnect').length, 1);

  env.replies.status = Object.assign({}, STATUS, { state: 'waiting', attempt: 5, killSwitch: { enabled: true, armed: true, blocking: false } });
  await v.refresh();
  assert.match(v.el.badge.textContent, /Waiting for internet… \(attempt 5\)/);
  assert.equal(v.el.ks.textContent, 'On — ready: it blocks only while the VPN is on and the tunnel is down');
  assert.equal(v.el.block.style.display, 'none');
  env.replies.status = Object.assign({}, STATUS, { state: 'disconnected', killSwitch: { enabled: true, armed: false, blocking: false } });
  await v.refresh();
  assert.equal(v.el.vpn.checked, false);
  assert.equal(v.el.ks.textContent, 'On — waits until the VPN is switched on');
  // the configs are re-read every 10th poll, not every time
  const before = callsOf(env, 'configs').length;
  for (let i = 0; i < 10; i++) await v.refresh();
  assert.equal(callsOf(env, 'configs').length - before, 1);
});

test('Overview: a service that is not running shows that and Start; an old service says update', async () => {
  const env = fakeLuci({ replies: healthy({ status: { error: 'not-running' }, configs: { error: 'not-running' } }), token: null });
  const { v, page } = await openView('overview', env);
  assert.equal(v.el.body.style.display, 'none');
  assert.match(v.el.problem.textContent, /The IRNetFree service is not running\./);
  assert.match(page.textContent, /No token yet/);
  env.calls.length = 0;
  await v.el.problem.button('Start the service').fire('click')[0];
  assert.deepEqual(callsOf(env, 'service').map((c) => c.params), [{ action: 'start' }]);
  assert.ok(callsOf(env, 'status').length >= 1, 'and the status is read again');

  env.replies.status = STATUS;
  await v.refresh();
  assert.equal(v.el.body.style.display, '');
  assert.equal(v.el.problem.childNodes.length, 0);

  const old = fakeLuci({ replies: healthy({ status: { error: 'http 405' } }) });
  const o = await openView('overview', old);
  assert.match(o.v.el.problem.textContent, /does not know this request yet — update IRNetFree/);
  assert.equal(o.v.el.problem.buttons().length, 0, 'no Start for a service that is running');
});

test('Overview in Persian', async () => {
  const env = fakeLuci({ lang: 'fa', replies: healthy() });
  const { v, page } = await openView('overview', env);
  const text = page.textContent;
  for (const s of ['متصل', 'وضعیت', 'کیل سوییچ', 'تست اتصال', 'به‌روزرسانی ساب‌ها', 'باز کردن رابط وب کامل']) assert.ok(text.includes(s), s);
  assert.deepEqual(v.el.picker.byTag('optgroup').map((g) => g.getAttribute('label')), ['My provider', 'کانفیگ‌های دستی']);
});

/* ------------------------------ Settings ------------------------------ */

test('Settings: the four router settings from the service, devices to pick from, the UCI port and address', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v } = await openView('settings', env);
  const [json, u] = env.maps;
  assert.equal(json.config, 'json');
  const opts = json.sections[0].options;
  assert.deepEqual(opts.map((o) => [o.option, o.constructor.name, o.rmempty]), [
    ['autoConnect', 'Flag', false], ['killSwitch', 'Flag', false], ['lanBlockQuic', 'Flag', false], ['lanBypassMacs', 'DynamicList', true]
  ]);
  assert.equal(opts[0].title, 'Connect when the router starts');
  assert.equal(opts[0].description, 'After a reboot or power cut the VPN comes back as it was');
  assert.match(opts[1].description, /never blocked/);
  assert.equal(opts[3].datatype, 'macaddr');
  // DHCP devices as choices: normalised, each MAC once, junk dropped
  assert.deepEqual(opts[3].keylist, ['aa:bb:cc:dd:ee:ff', '02:00:00:00:00:01']);
  assert.deepEqual(opts[3].vallist, ['laptop (192.168.1.20, aa:bb:cc:dd:ee:ff)', 'Unknown device (192.168.1.21, 02:00:00:00:00:01)']);
  // the loaded values, as LuCI's Flag reads them
  assert.equal(json.data.get('json', 'settings', 'autoConnect'), '1');
  assert.equal(json.data.get('json', 'settings', 'killSwitch'), '0');
  assert.deepEqual(json.data.get('json', 'settings', 'lanBypassMacs'), ['02:00:00:00:00:01']);
  // the web UI's own settings, in UCI
  assert.equal(u.config, 'irnetfree');
  assert.equal(u.sections[0].section, 'main');
  assert.deepEqual(u.sections[0].options.map((o) => [o.option, o.datatype]), [['port', 'port'], ['bind', 'ipaddr']]);
  assert.match(u.description, /restarts the service/);
  assert.equal(typeof v.handleSave, 'function');
});

test('Settings: Save sends only what changed and the service applies it; Save & Apply commits staged UCI', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v } = await openView('settings', env);
  const [json, u] = env.maps;
  env.calls.length = 0;

  // nothing touched: no call at all
  await v.handleSave();
  assert.equal(callsOf(env, 'settings_set').length, 0);
  assert.equal(u.saves, 1, 'the UCI form is saved (staged) as on any LuCI page');

  json.option('settings', 'killSwitch').formValue = true;
  json.option('settings', 'lanBypassMacs').formValue = ['02:00:00:00:00:01', 'AA:BB:CC:DD:EE:FF'];
  await v.handleSave();
  assert.deepEqual(callsOf(env, 'settings_set').map((c) => c.params), [{ killSwitch: true, lanBypassMacs: ['02:00:00:00:00:01', 'aa:bb:cc:dd:ee:ff'] }]);
  assert.match(env.ui.notes.pop().textContent, /Saved — applied/);
  // saved again unchanged: nothing new is sent
  await v.handleSave();
  assert.equal(callsOf(env, 'settings_set').length, 1);
  // a bad MAC never leaves the page
  json.option('settings', 'lanBypassMacs').formValue = ['nope'];
  await assert.rejects(v.handleSave());
  assert.equal(callsOf(env, 'settings_set').length, 1);
  json.option('settings', 'lanBypassMacs').formValue = undefined;

  // Save & Apply with nothing staged in UCI: no apply (LuCI would only say "no changes")
  await v.handleSaveApply(null, '0');
  assert.deepEqual(env.ui.applied, []);
  env.uciChanges = { irnetfree: [['set', 'main', 'port', '7000']] };
  await v.handleSaveApply(null, '0');
  assert.deepEqual(env.ui.applied, [true], 'applied with rollback, like LuCI\'s own button');
  await v.handleSaveApply(null, '1');
  assert.deepEqual(env.ui.applied, [true, false]);

  // the service refuses: the error is shown and the save fails
  env.replies.settings_set = { error: 'lanBypassMacs: too many' };
  json.option('settings', 'autoConnect').formValue = false;
  await assert.rejects(v.handleSave());
  assert.match(env.ui.notes.pop().textContent, /Error: lanBypassMacs: too many/);
});

test('Settings: with the service down the router settings say so (with Start) and the UCI form still works', async () => {
  const env = fakeLuci({ replies: healthy({ settings_get: { error: 'not-running' }, devices: { error: 'not-running' } }) });
  const { v, page } = await openView('settings', env);
  assert.equal(env.maps.length, 1, 'only the UCI form');
  assert.equal(env.maps[0].config, 'irnetfree');
  assert.match(page.textContent, /The IRNetFree service is not running\./);
  env.calls.length = 0;
  await page.button('Start the service').fire('click')[0];
  assert.deepEqual(callsOf(env, 'service').map((c) => c.params), [{ action: 'start' }]);
  await v.handleSave();
  assert.equal(callsOf(env, 'settings_set').length, 0);
  assert.equal(env.maps[0].saves, 1);
});

/* ------------------------------ Remote access ------------------------------ */

test('Remote access: relay and Cloudflare Tunnel with their live states; tokens are write-only', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v, page } = await openView('remote', env);
  const m = env.maps[0];
  assert.deepEqual(m.sections.map((s) => s.section), ['relay', 'cloudflared']);
  assert.deepEqual(m.sections[0].options.map((o) => o.option), ['enabled', 'relayUrl', 'name', 'token', '_state']);
  assert.deepEqual(m.sections[1].options.map((o) => o.option), ['_installed', 'enabled', 'token', '_state']);
  const relayToken = m.option('relay', 'token'), cfToken = m.option('cloudflared', 'token');
  assert.equal(relayToken.password, true);
  assert.equal(cfToken.password, true);
  assert.equal(m.data.get('json', 'relay', 'token'), null, 'the token field starts empty');
  assert.equal(relayToken.description, 'A token is set. Type a new one only to replace it.');
  assert.match(cfToken.description, /^Not set yet/);
  assert.equal(m.data.get('json', 'relay', 'relayUrl'), 'https://relay.example.com');
  assert.match(m.sections[1].description, /http:\/\/127\.0\.0\.1:6969/);
  assert.match(page.textContent, /online \(direct\)/);
  assert.match(page.textContent, /Open the relay/);
  assert.match(page.textContent, /Not installed/);
  assert.deepEqual(env.poll.added.map((p) => p.interval), [5]);

  env.calls.length = 0;
  await v.handleSave();
  assert.equal(callsOf(env, 'remote_set').length, 0, 'nothing changed, nothing sent');
  assert.match(env.ui.notes.pop().textContent, /Nothing changed/);

  m.option('relay', 'relayUrl').formValue = 'https://relay.example.org';
  relayToken.formValue = 'new-device-token';
  await v.handleSave();
  assert.deepEqual(callsOf(env, 'remote_set').map((c) => c.params), [{ relay: { relayUrl: 'https://relay.example.org', token: 'new-device-token' } }]);
  assert.equal(m.data.get('json', 'relay', 'token'), null, 'the typed token leaves the page');
  assert.equal(m.resets, 1);

  relayToken.formValue = undefined;
  m.option('cloudflared', 'enabled').formValue = true;
  cfToken.formValue = 'cf-token';
  await v.handleSave();
  assert.deepEqual(callsOf(env, 'remote_set')[1].params, { cloudflared: { enabled: true, token: 'cf-token' } });
  assert.equal(cfToken.description, 'A token is set. Type a new one only to replace it.');

  m.option('relay', 'relayUrl').formValue = 'http://insecure.example.com/path';
  await assert.rejects(v.handleSave());
  assert.equal(callsOf(env, 'remote_set').length, 2, 'an invalid URL never leaves the page');
});

test('Remote access: Install cloudflared, then the page follows remote_status until it is in', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v, page } = await openView('remote', env);
  env.calls.length = 0;
  await page.button('Install').fire('click')[0];
  assert.equal(callsOf(env, 'cloudflared_install').length, 1);
  assert.match(v.el.cfInstalled.textContent, /Installing…/);
  env.replies.remote_status = { relay: { state: 'connecting' }, cloudflared: { installed: true, running: true, lastLine: 'Registered tunnel connection' } };
  await env.poll.added[0].fn();
  assert.equal(v.el.cfInstalled.textContent, 'Installed');
  assert.equal(v.el.cfState.textContent, 'running — Registered tunnel connection');
  assert.equal(v.el.relayState.textContent, 'connecting…');
  assert.match(env.ui.notes.pop().textContent, /cloudflared is installed/);
});

test('Remote access: a service without the remote module, or not running', async () => {
  const env = fakeLuci({ replies: healthy({ remote_get: { error: 'remote not available' }, remote_status: { error: 'remote not available' } }) });
  const { page } = await openView('remote', env);
  assert.match(page.textContent, /Remote access is not part of this IRNetFree version/);
  assert.equal(env.maps.length, 0);
  const down = fakeLuci({ replies: healthy({ remote_get: { error: 'not-running' } }) });
  const d = await openView('remote', down);
  assert.ok(d.page.button('Start the service'));
  assert.equal(await d.v.handleSave(), undefined, 'Save does nothing without a form');
});

/* ------------------------------ Log ------------------------------ */

test('Log: the ring\'s lines, Refresh, and Copy diagnostics with its fallback', async () => {
  const env = fakeLuci({ replies: healthy() });
  const { v, page } = await openView('log', env);
  assert.deepEqual(callsOf(env, 'log').map((c) => c.params), [{ lines: 300 }]);
  assert.equal(v.pre.textContent, 'irnetfree: connected — ci-upstream\nirnetfree: stats');
  assert.equal(v.pre.getAttribute('dir'), 'ltr', 'a log stays left-to-right in a Persian LuCI');
  env.replies.log = { lines: [] };
  await page.button('Refresh').fire('click')[0];
  assert.equal(v.pre.textContent, 'The log is empty.');

  await page.button('Copy diagnostics').fire('click')[0];
  assert.match(env.ui.notes.pop().textContent, /Diagnostics copied/);
  assert.equal(env.document.body.childNodes.length, 0, 'the helper textarea is gone again');
  env.execCopy = false;
  await v.handleCopy();
  const modal = env.ui.modals.pop();
  const ta = modal.node.byTag('textarea')[0];
  assert.equal(ta.value, 'status: connected\nMemAvailable: 200000 kB');
  assert.equal(v.handleSave, null);

  env.replies.log = { error: 'not-running' };
  await v.handleRefresh();
  assert.match(page.textContent, /The IRNetFree service is not running\./);
  assert.equal(v.pre.textContent, '');
});
