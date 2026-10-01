'use strict';
'require view';
'require form';
'require ui';
'require uci';
'require irnetfree.common as common';

/*
 * Services → IRNetFree → Settings. Two forms:
 *  - the router settings the service keeps (connect when the router starts,
 *    kill switch, QUIC, devices that bypass the VPN): read with settings_get,
 *    saved with settings_set — only what changed — and applied by the service
 *    at once, on Save as on Save & Apply;
 *  - the web UI's port and listen address, which live in UCI
 *    (/etc/config/irnetfree): Save stages them like any LuCI page, Save &
 *    Apply commits them and procd restarts the service with the new values.
 * The UCI form is shown even when the service does not answer — a port clash
 * is exactly when it is needed.
 */

var FLAGS = [ 'autoConnect', 'killSwitch', 'lanBlockQuic' ];

return view.extend({
	load: function () {
		return Promise.all([
			common.settingsGet(),
			common.devices(),
			L.resolveDefault(uci.load('irnetfree'), null)
		]);
	},

	render: function (data) {
		var settings = data[0], devices = common.list(data[1]);
		var nodes = [];
		var m, s, o;

		this.jsonMap = null;
		if (common.errorOf(settings)) {
			nodes.push(Promise.resolve(E('div', { 'class': 'cbi-section' }, [
				E('h2', {}, [ common.t('IRNetFree settings') ]),
				common.problemBox(settings, function () { window.setTimeout(function () { window.location.reload(); }, 3000); })
			])));
		}
		else {
			this.loaded = common.routerSettings(settings);
			var initial = { lanBypassMacs: this.loaded.lanBypassMacs.slice() };
			FLAGS.forEach(L.bind(function (k) { initial[k] = this.loaded[k] ? '1' : '0'; }, this));

			m = new form.JSONMap({ settings: initial }, common.t('IRNetFree settings'),
				common.t('Saved changes take effect at once — no restart, no reconnect.'));
			s = m.section(form.NamedSection, 'settings', 'settings');

			o = s.option(form.Flag, 'autoConnect', common.t('Connect when the router starts'),
				common.t('After a reboot or power cut the VPN comes back as it was'));
			o.rmempty = false;

			o = s.option(form.Flag, 'killSwitch', common.t('Kill switch'),
				common.t('While the VPN is switched on and the tunnel is not up — a drop, a reconnect, the router starting — devices on the LAN get no internet instead of going out unprotected. Devices that bypass the VPN, traffic inside the LAN and the router’s own traffic are never blocked. Turning the VPN off gives the LAN normal internet.'));
			o.rmempty = false;

			o = s.option(form.Flag, 'lanBlockQuic', common.t('Block QUIC from the LAN'),
				common.t('Browsers fall back to TCP at once, which every proxy carries; devices that bypass the VPN are not affected.'));
			o.rmempty = false;

			o = s.option(form.DynamicList, 'lanBypassMacs', common.t('Devices that bypass the VPN'),
				common.t('These devices reach the internet directly, not through the tunnel. Pick one the router has given an address to, or type a MAC address.'));
			o.datatype = 'macaddr';
			var seen = {};
			devices.forEach(function (d) {
				var mac = common.normMac(d && d.mac);
				if (!common.isMac(mac) || seen[mac]) return;
				seen[mac] = true;
				o.value(mac, common.deviceLabel(d));
			});

			this.jsonMap = m;
			nodes.push(m.render());
		}

		m = new form.Map('irnetfree', common.t('Web UI'),
			common.t('The port and address the IRNetFree web UI listens on. Save & Apply restarts the service: a few seconds, then the tunnel comes back by itself.'));
		s = m.section(form.NamedSection, 'main', 'irnetfree');
		o = s.option(form.Value, 'port', common.t('Port'));
		o.datatype = 'port';
		o.placeholder = '6969';
		o.rmempty = false;
		o = s.option(form.Value, 'bind', common.t('Listen address'));
		o.datatype = 'ipaddr';
		o.placeholder = '0.0.0.0';
		o.value('0.0.0.0', common.t('Every interface (0.0.0.0)'));
		o.value('127.0.0.1', common.t('This router only (127.0.0.1)'));
		this.uciMap = m;
		nodes.push(m.render());

		return Promise.all(nodes).then(function (n) { return E('div', {}, n); });
	},

	/* the router settings as the form has them now */
	formSettings: function () {
		var m = this.jsonMap;
		var get = function (k) { return m.data.get('json', 'settings', k); };
		var out = {};
		FLAGS.forEach(function (k) { out[k] = get(k) === '1'; });
		out.lanBypassMacs = L.toArray(get('lanBypassMacs')).map(common.normMac).filter(common.isMac);
		return out;
	},

	/* validate the router form, then send what changed; the service applies it at once */
	saveSettings: function () {
		var self = this;
		if (!this.jsonMap) return Promise.resolve();
		return this.jsonMap.save().then(function () {
			var next = self.formSettings();
			var diff = common.changed(self.loaded, next);
			if (!diff) return;
			return common.settingsSet(diff.autoConnect, diff.killSwitch, diff.lanBlockQuic, diff.lanBypassMacs).then(function (r) {
				var err = common.errorOf(r);
				if (err) {
					common.notify(err, 'danger');
					throw new Error(err);
				}
				self.loaded = r && r.settings ? common.routerSettings(r.settings) : next;
				common.notify(common.t('Saved — applied.'));
			});
		});
	},

	handleSave: function (ev) {
		var self = this;
		return this.saveSettings().then(function () {
			return self.uciMap.save();
		});
	},

	handleSaveApply: function (ev, mode) {
		return this.handleSave(ev).then(function () {
			return L.resolveDefault(uci.changes(), {});
		}).then(function (changes) {
			// UCI changes staged (here or on another page): commit them the LuCI way
			if (changes && Object.keys(changes).length)
				ui.changes.apply(mode == '0');
		});
	}
});
