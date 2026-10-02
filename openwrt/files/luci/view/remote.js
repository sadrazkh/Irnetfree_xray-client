'use strict';
'require view';
'require form';
'require poll';
'require ui';
'require dom';
'require uci';
'require irnetfree.common as common';

/*
 * Services → IRNetFree → Remote access: the relay (your own server the router
 * keeps a link to) and Cloudflare Tunnel, each with its live state. The
 * settings live in the service (remote_get / remote_set); Save sends only
 * what changed and the service applies it at once. Tokens are write-only:
 * the service only ever says whether one is set, the fields start empty, and a
 * token is sent only when one was typed. The states are re-read every 5 s.
 */

return view.extend({
	load: function () {
		return Promise.all([
			common.remoteGet(),
			common.remoteStatus(),
			L.resolveDefault(uci.load('irnetfree'), null)
		]);
	},

	render: function (data) {
		var self = this, conf = data[0];
		var el = this.el = {};
		this.map = null;

		if (common.errorOf(conf)) {
			return E('div', { 'class': 'cbi-map' }, [
				E('h2', {}, [ common.t('Remote access') ]),
				common.problemBox(conf, common.reloadWhenUp)
			]);
		}

		var relay = conf.relay || {}, cf = conf.cloudflared || {};
		this.loaded = {
			relay: { enabled: !!relay.enabled, relayUrl: String(relay.relayUrl || ''), name: String(relay.name || '') },
			cloudflared: { enabled: !!cf.enabled }
		};
		this.tokenSet = { relay: !!relay.tokenSet, cloudflared: !!cf.tokenSet };
		this.cfInstalled = !!cf.installed;

		el.relayState = E('span', {});
		el.relayOpen = E('span', {});
		el.cfInstalled = E('span', {});
		el.cfState = E('span', {});

		var m = new form.JSONMap({
			relay: {
				enabled: this.loaded.relay.enabled ? '1' : '0',
				relayUrl: this.loaded.relay.relayUrl,
				name: this.loaded.relay.name
			},
			cloudflared: {
				enabled: this.loaded.cloudflared.enabled ? '1' : '0'
			}
		}, common.t('Remote access'),
			common.t('Control this router from outside the home — turn the VPN on or off, change the config — without a static IP, even behind CGNAT. The control link never goes through the VPN. Both ways can be on at once.'));

		var s = m.section(form.NamedSection, 'relay', 'relay', common.t('Your own relay'),
			common.t('A small server you run (on Harbora or any Docker host) that this router keeps a link to. Add the router on the relay, then paste the device token it shows here.'));
		var o = s.option(form.Flag, 'enabled', common.t('Enabled'));
		o.rmempty = false;
		o = s.option(form.Value, 'relayUrl', common.t('Relay URL'));
		o.placeholder = 'https://relay.example.com';
		o.validate = function (section_id, value) {
			return (!value || common.validRelayUrl(value)) ? true : common.t('Use https:// and a host name, with no path.');
		};
		o = s.option(form.Value, 'name', common.t('Router name'), common.t('Up to 40 characters.'));
		o.placeholder = common.t('home');
		o.validate = function (section_id, value) {
			return common.validRouterName(value) ? true : common.t('Up to 40 characters.');
		};
		this.relayToken = o = s.option(form.Value, 'token', common.t('Device token'), this.tokenText('relay'));
		o.password = true;
		o = s.option(form.DummyValue, '_state', common.t('State'));
		o.renderWidget = function () { return E('div', {}, [ el.relayState, ' ', el.relayOpen ]); };

		s = m.section(form.NamedSection, 'cloudflared', 'cloudflared', common.t('Cloudflare Tunnel'),
			common.t('A second way in, through Cloudflare: create a tunnel in the Cloudflare dashboard, point its public hostname at http://127.0.0.1:%s and protect it with Cloudflare Access, then paste the tunnel token here.',
				uci.get('irnetfree', 'main', 'port') || '6969'));
		o = s.option(form.DummyValue, '_installed', common.t('cloudflared program'));
		o.renderWidget = function () { return el.cfInstalled; };
		o = s.option(form.Flag, 'enabled', common.t('Enabled'));
		o.rmempty = false;
		this.cfToken = o = s.option(form.Value, 'token', common.t('Tunnel token'), this.tokenText('cloudflared'));
		o.password = true;
		o = s.option(form.DummyValue, '_state', common.t('State'));
		o.renderWidget = function () { return el.cfState; };

		this.map = m;
		this.showInstalled();
		this.applyState(data[1]);
		poll.add(L.bind(this.refresh, this), 5);
		return m.render();
	},

	tokenText: function (which) {
		if (this.tokenSet[which]) return common.t('A token is set. Type a new one only to replace it.');
		return which === 'relay'
			? common.t('Not set yet: paste the token the relay showed when you added this router.')
			: common.t('Not set yet: paste the token of the tunnel you created in the Cloudflare dashboard.');
	},

	showInstalled: function () {
		var el = this.el;
		if (this.cfInstalled) {
			dom.content(el.cfInstalled, [ common.t('Installed') ]);
		}
		else if (this.installing) {
			dom.content(el.cfInstalled, [ common.t('Installing… (opkg update, then opkg install cloudflared — this can take a few minutes)') ]);
		}
		else {
			dom.content(el.cfInstalled, [
				common.t('Not installed'), ' ',
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, 'handleInstall') }, [ common.t('Install') ])
			]);
		}
	},

	refresh: function () {
		var self = this;
		return common.remoteStatus().then(function (st) { self.applyState(st); }, function () { self.applyState(null); });
	},

	applyState: function (st) {
		var el = this.el;
		if (common.errorOf(st)) {
			el.relayState.textContent = common.errorOf(st);
			el.cfState.textContent = '';
			return;
		}
		el.relayState.textContent = common.relayText(st.relay);
		var url = this.loaded.relay.relayUrl;
		dom.content(el.relayOpen, (url && common.validRelayUrl(url) && st.relay && st.relay.state === 'online')
			? [ E('a', { 'href': url, 'target': '_blank', 'rel': 'noopener' }, [ common.t('Open the relay') ]) ]
			: null);
		var c = st.cloudflared || {};
		el.cfState.textContent = common.cloudflaredText(c) + (c.installed && c.lastLine ? ' — ' + c.lastLine : '');
		if (c.installed && !this.cfInstalled) {
			this.cfInstalled = true;
			this.installing = false;
			this.showInstalled();
			common.notify(common.t('cloudflared is installed.'));
		}
	},

	handleInstall: function () {
		var self = this;
		return common.cloudflaredInstall().then(function (r) {
			var err = common.errorOf(r);
			if (err) return common.notify(err, 'danger');
			self.installing = true;
			self.showInstalled();
		}, common.failed);
	},

	handleSave: function () {
		var self = this, m = this.map;
		if (!m) return Promise.resolve();
		return m.save().then(function () {
			var get = function (sec, k) { return m.data.get('json', sec, k); };
			var relay = {}, cf = {}, any = false;
			var next = {
				relay: { enabled: get('relay', 'enabled') === '1', relayUrl: String(get('relay', 'relayUrl') || ''), name: String(get('relay', 'name') || '') },
				cloudflared: { enabled: get('cloudflared', 'enabled') === '1' }
			};
			var d = common.changed(self.loaded.relay, next.relay);
			if (d) { relay = d; any = true; }
			d = common.changed(self.loaded.cloudflared, next.cloudflared);
			if (d) { cf = d; any = true; }
			// write-only tokens: only when one was typed
			var rt = get('relay', 'token'), ct = get('cloudflared', 'token');
			if (rt) { relay.token = String(rt); any = true; }
			if (ct) { cf.token = String(ct); any = true; }
			if (!any) {
				common.notify(common.t('Nothing changed.'));
				return;
			}
			return common.remoteSet(Object.keys(relay).length ? relay : undefined, Object.keys(cf).length ? cf : undefined).then(function (r) {
				var err = common.errorOf(r);
				if (err) {
					common.notify(err, 'danger');
					throw new Error(err);
				}
				self.loaded = next;
				if (rt) self.tokenSet.relay = true;
				if (ct) self.tokenSet.cloudflared = true;
				// the typed tokens leave the page: the fields are empty again and say "set"
				m.data.unset('json', 'relay', 'token');
				m.data.unset('json', 'cloudflared', 'token');
				self.relayToken.description = self.tokenText('relay');
				self.cfToken.description = self.tokenText('cloudflared');
				common.notify(common.t('Saved — applied.'));
				return m.reset();
			}, function (e) {
				// the call itself failed (no write access, a timeout): say why, and the save failed
				common.failed(e);
				throw e;
			});
		});
	},

	handleSaveApply: null
});
