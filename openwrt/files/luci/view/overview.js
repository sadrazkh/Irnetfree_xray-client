'use strict';
'require view';
'require dom';
'require poll';
'require ui';
'require fs';
'require uci';
'require irnetfree.common as common';

/*
 * Services → IRNetFree → Overview: the state of the tunnel and the VPN switch,
 * the config picker with Connect / Reconnect / Test connection / Update
 * subscriptions, the kill switch and remote-access states, and the link to the
 * full web UI. Every control acts at once — there is no Save. The status is
 * read every 3 s, the config list every 30 s and soon after a subscription
 * update. Text from the service (config names, errors) only ever goes in as
 * text nodes, never as HTML.
 */

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, [ label ]),
		E('td', { 'class': 'td left' }, [ value ])
	]);
}

function button(cls, label, handler) {
	return E('button', { 'class': 'btn cbi-button ' + cls, 'click': handler }, [ label ]);
}

return view.extend({
	load: function () {
		return Promise.all([
			common.status(),
			common.configs(),
			L.resolveDefault(fs.read('/etc/irnetfree/token'), ''),
			L.resolveDefault(uci.load('irnetfree'), null)
		]);
	},

	render: function (data) {
		var el = this.el = {};
		var token = String(data[2] || '').trim();
		var port = uci.get('irnetfree', 'main', 'port') || '6969';
		this.tick = 0;
		this.cfgDue = 10;
		this.busy = false;

		el.problem = E('div', {});
		el.version = E('span', {});
		el.badge = E('span', {});
		el.vpn = E('input', { 'type': 'checkbox', 'id': 'irnf-vpn', 'change': ui.createHandlerFn(this, 'handleSwitch') });
		el.vpnText = E('label', { 'for': 'irnf-vpn', 'style': 'margin:0 .5em' });
		el.config = E('span', {});
		el.uptime = E('span', {});
		el.traffic = E('span', {});
		el.ks = E('span', {});
		el.remote = E('span', {});
		el.remoteRow = row(common.t('Remote access'), el.remote);
		el.block = E('div', { 'class': 'alert-message danger', 'style': 'display:none' }, [
			E('p', {}, [ common.t('LAN internet is blocked until the VPN is back.') ]),
			button('cbi-button-negative', common.t('Turn the VPN off'), ui.createHandlerFn(this, 'handleTurnOff'))
		]);
		el.picker = E('select', { 'class': 'cbi-input-select', 'id': 'irnf-picker', 'style': 'min-width:18em;max-width:100%', 'change': ui.createHandlerFn(this, 'handleSelect') });
		el.cfgNote = E('p', {});
		el.result = E('span', { 'style': 'margin:0 .5em' });

		el.body = E('div', {}, [
			el.block,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ common.t('Status') ]),
				E('table', { 'class': 'table' }, [
					row(common.t('Connection'), el.badge),
					row(common.t('VPN'), E('span', {}, [ el.vpn, el.vpnText ])),
					row(common.t('Config'), el.config),
					row(common.t('Connected for'), el.uptime),
					row(common.t('Traffic'), el.traffic),
					row(common.t('Kill switch'), el.ks),
					el.remoteRow
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ common.t('Configs') ]),
				E('p', {}, [ common.t('Pick a config, then Connect. Choosing one here also selects it in the web UI.') ]),
				E('div', {}, [ el.picker ]),
				el.cfgNote,
				E('div', { 'style': 'margin-top:.5em' }, [
					button('cbi-button-apply', common.t('Connect'), ui.createHandlerFn(this, 'handleConnect')), ' ',
					button('cbi-button-action', common.t('Reconnect'), ui.createHandlerFn(this, 'handleReconnect')), ' ',
					button('cbi-button-neutral', common.t('Test connection'), ui.createHandlerFn(this, 'handleTest')), ' ',
					button('cbi-button-neutral', common.t('Update subscriptions'), ui.createHandlerFn(this, 'handleUpdateSubs')),
					el.result
				])
			])
		]);

		var page = E('div', { 'class': 'cbi-map', 'id': 'irnf-overview' }, [
			E('h2', {}, [ 'IRNetFree' ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				common.t('The tunnel for every device behind this router. Changes on this page take effect at once.'), ' ', el.version
			]),
			el.problem,
			el.body,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ common.t('Web UI') ]),
				E('p', {}, [ common.t('The full IRNetFree web UI has everything else: servers, subscriptions, routing, chains and logs.') ]),
				E('p', {}, [
					E('a', {
						'class': 'btn cbi-button cbi-button-action',
						'href': common.webUiUrl(window.location.hostname, port, token),
						'target': '_blank',
						'rel': 'noopener'
					}, [ common.t('Open full web UI') ])
				]),
				token ? '' : E('p', { 'class': 'alert-message warning' }, [ common.t('No token yet: start the service and reload this page.') ])
			])
		]);

		this.applyStatus(data[0]);
		this.applyConfigs(data[1]);
		poll.add(L.bind(this.refresh, this), 3);
		poll.add(L.bind(this.showUptime, this), 1);
		return page;
	},

	/* the poll: the status every time, the configs every 10th time or when due */
	refresh: function () {
		var self = this;
		this.tick++;
		var withConfigs = this.tick >= this.cfgDue;
		return Promise.all([ common.status(), withConfigs ? common.configs() : null ]).then(function (r) {
			self.applyStatus(r[0]);
			if (withConfigs) {
				self.cfgDue = self.tick + 10;
				self.applyConfigs(r[1]);
			}
		}, function () {
			// the router itself did not answer (a reboot, LuCI's session ended): say so, keep polling
			self.applyStatus(null);
		});
	},

	applyStatus: function (st) {
		var el = this.el;
		var err = common.errorOf(st);
		if (err) {
			this.since = null;
			dom.content(el.problem, [ common.problemBox(st, L.bind(this.refresh, this)) ]);
			el.body.style.display = 'none';
			return;
		}
		dom.content(el.problem, null);
		el.body.style.display = '';
		el.version.textContent = st.version ? common.t('Version %s', st.version) : '';

		dom.content(el.badge, [ common.renderBadge(common.badge(st.state, st.attempt, st.reason)) ]);
		var on = common.vpnOn(st.state);
		if (!this.busy) el.vpn.checked = on;
		el.vpnText.textContent = on ? common.t('On') : common.t('Off');
		el.config.textContent = st.label ? (st.engine ? st.label + ' (' + st.engine + ')' : String(st.label)) : '—';
		this.since = (st.state === 'connected' && st.since) ? +st.since : null;
		this.showUptime();
		el.traffic.textContent = common.traffic(st.traffic);

		var ks = st.killSwitch || {};
		el.ks.textContent = !ks.enabled ? common.t('Off')
			: ks.blocking ? common.t('On — blocking')
			: ks.armed ? common.t('On — ready: it blocks only while the VPN is on and the tunnel is down')
			: common.t('On — waits until the VPN is switched on');
		el.block.style.display = ks.blocking ? '' : 'none';

		var remote = common.remoteLine(st.remote);
		el.remote.textContent = remote || '';
		el.remoteRow.style.display = remote ? '' : 'none';
	},

	applyConfigs: function (cf) {
		var el = this.el;
		var err = common.errorOf(cf);
		if (err) {
			el.cfgNote.textContent = err;
			return;
		}
		this.cf = cf;
		var groups = (Array.isArray(cf.groups) ? cf.groups : []).filter(function (g) {
			return g && Array.isArray(g.items) && g.items.length;
		});
		var picked = this.pickedId || cf.selectedId || cf.activeId || '';
		// rebuilt only when the list changed: a poll must not close the dropdown under the user
		var sig = JSON.stringify([ groups, cf.activeId, picked ]);
		if (sig === this.cfgSig) return;
		this.cfgSig = sig;
		el.cfgNote.textContent = groups.length ? '' : common.t('No configs yet — add servers or a subscription in the web UI.');
		dom.content(el.picker, groups.map(function (g) {
			return E('optgroup', { 'label': common.groupLabel(g) }, g.items.map(function (it) {
				return E('option', { 'value': String(it.id), 'selected': String(it.id) === String(picked) ? 'selected' : null },
					[ common.itemLabel(it, it.id === cf.activeId) ]);
			}));
		}));
		if (picked) el.picker.value = String(picked);
	},

	showUptime: function () {
		this.el.uptime.textContent = this.since ? common.duration((Date.now() - this.since) / 1000) : '—';
	},

	/* the id the picker shows, else the service's selection */
	currentId: function () {
		var v = this.el.picker.value;
		if (v) return v;
		return (this.cf && (this.cf.selectedId || this.cf.activeId)) || '';
	},

	/* run an action, report a refusal, then show the new state at once */
	act: function (p) {
		var self = this;
		this.busy = true;
		var done = function () { self.busy = false; };
		return p.then(function (r) {
			var err = common.errorOf(r);
			if (err) common.notify(err, 'danger');
			done();
			return self.refresh();
		}, function (e) {
			done();
			throw e;
		});
	},

	handleSwitch: function (ev) {
		var on = !!(ev && ev.currentTarget && ev.currentTarget.checked);
		if (!on) return this.act(common.disconnect());
		var id = this.currentId();
		if (!id) {
			this.el.vpn.checked = false;
			common.notify(common.t('Choose a config first.'), 'warning');
			return Promise.resolve();
		}
		return this.act(common.connect(id));
	},

	handleConnect: function () {
		var id = this.currentId();
		if (!id) {
			common.notify(common.t('Choose a config first.'), 'warning');
			return Promise.resolve();
		}
		return this.act(common.connect(id));
	},

	handleReconnect: function () {
		return this.act(common.reconnect());
	},

	handleTurnOff: function () {
		return this.act(common.disconnect());
	},

	handleSelect: function () {
		var id = this.el.picker.value;
		this.pickedId = id;
		return common.select(id).then(function (r) {
			var err = common.errorOf(r);
			if (err) common.notify(err, 'danger');
		});
	},

	handleTest: function () {
		var out = this.el.result;
		out.textContent = common.t('Testing…');
		return common.test().then(function (r) {
			if (r && r.ok) out.textContent = common.t('Test: %s ms', r.ms);
			else if (r && r.ok === false) out.textContent = common.t('Test failed: %s', r.error || '?');
			else out.textContent = common.t('Test failed: %s', common.errorOf(r) || '?');
		});
	},

	handleUpdateSubs: function () {
		var self = this;
		return common.subsUpdate().then(function (r) {
			var err = common.errorOf(r);
			if (err) return common.notify(err, 'danger');
			common.notify(common.t('Updating subscriptions — the list refreshes when they are done.'));
			self.cfgDue = self.tick + 4;
		});
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
