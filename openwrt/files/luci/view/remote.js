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
 * settings live in the service (remote_get / remote_set); nothing here acts
 * before Save, which sends only what changed, and the service applies it at
 * once. Tokens are write-only: the service only ever says whether one is set,
 * the fields start empty, and a token is sent only when one was typed.
 * «Enabled» is checked on the page the way remote_set checks it — the relay
 * needs its URL and a device token, Cloudflare needs cloudflared and a tunnel
 * token — and a refused Save is a dialog with the reason (v1.16.1: a refusal
 * used to be a notice at the top, in English, easy to miss). The states are
 * re-read every 5 s.
 */

/* What an option holds now: its widget's value, else what it was rendered with. */
function formOf(o, sid) {
	var v = (o && typeof o.formvalue === 'function') ? o.formvalue(sid) : null;
	return (v == null && o) ? o.cfgvalue(sid) : v;
}

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
		this.opts = { relay: {}, cloudflared: {} };
		this.pollSeq = 0;         // every status read is numbered when it leaves
		this.installAfter = -1;   // the reads that left before Install was accepted
		this.installing = false;
		this.installError = null;

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
			common.t('Control this router from outside the home — turn the VPN on or off, change the config — without a static IP, even behind CGNAT. The control link never goes through the VPN. Both ways can be on at once.') + ' ' +
			common.t('Changes take effect only when you press Save at the bottom of the page.'));

		var enabledCheck = function (section_id) { return self.enableProblem(section_id) || true; };
		var recheck = function (section_id) { self.recheck(section_id); return true; };

		var s = m.section(form.NamedSection, 'relay', 'relay', common.t('Your own relay'));
		// what the relay is, before anything is asked: there is no relay unless you run one
		var o = s.option(form.DummyValue, '_about');
		o.renderWidget = function () {
			return E('div', { 'class': 'alert-message notice' }, [
				E('p', {}, [ common.t('The relay is a server you run yourself; IRNetFree does not provide one. Deploy relay/ on Harbora or any Docker host, press Add router on the relay’s page, then paste the relay URL and the 43-character device token here.') ]),
				E('p', {}, [ E('a', { 'href': common.remoteGuide, 'target': '_blank', 'rel': 'noopener' }, [ common.t('Step-by-step guide: docs/remote.md') ]) ])
			]);
		};
		this.opts.relay.enabled = o = s.option(form.Flag, 'enabled', common.t('Enabled'));
		o.rmempty = false;
		o.validate = enabledCheck;
		this.opts.relay.relayUrl = o = s.option(form.Value, 'relayUrl', common.t('Relay URL'));
		o.placeholder = 'https://relay.example.com';
		o.validate = function (section_id, value) {
			self.recheck(section_id);
			return (!value || common.validRelayUrl(value)) ? true : common.t('Use https:// and a host name, with no path.');
		};
		o = s.option(form.Value, 'name', common.t('Router name'), common.t('Up to 40 characters.'));
		o.placeholder = common.t('home');
		o.validate = function (section_id, value) {
			return common.validRouterName(value) ? true : common.t('Up to 40 characters.');
		};
		this.relayToken = this.opts.relay.token = o = s.option(form.Value, 'token', common.t('Device token'), this.tokenText('relay'));
		o.password = true;
		o.validate = recheck;
		o = s.option(form.DummyValue, '_state', common.t('State'));
		o.renderWidget = function () { return E('div', {}, [ el.relayState, ' ', el.relayOpen ]); };

		s = m.section(form.NamedSection, 'cloudflared', 'cloudflared', common.t('Cloudflare Tunnel'),
			common.t('A second way in, through Cloudflare: create a tunnel in the Cloudflare dashboard, point its public hostname at http://127.0.0.1:%s and protect it with Cloudflare Access, then paste the tunnel token here.',
				uci.get('irnetfree', 'main', 'port') || '6969'));
		o = s.option(form.DummyValue, '_installed', common.t('cloudflared program'));
		o.renderWidget = function () { return el.cfInstalled; };
		this.opts.cloudflared.enabled = o = s.option(form.Flag, 'enabled', common.t('Enabled'));
		o.rmempty = false;
		o.validate = enabledCheck;
		this.cfToken = this.opts.cloudflared.token = o = s.option(form.Value, 'token', common.t('Tunnel token'), this.tokenText('cloudflared'));
		o.password = true;
		o.validate = recheck;
		o = s.option(form.DummyValue, '_state', common.t('State'));
		o.renderWidget = function () { return el.cfState; };

		this.map = m;
		this.rendered = false;
		this.showInstalled();
		this.applyState(data[1], 0);
		poll.add(L.bind(this.refresh, this), 5);
		// the form's widgets exist only once it is rendered: LuCI reaches them through the map's root
		return m.render().then(function (node) { self.rendered = true; return node; });
	},

	tokenText: function (which) {
		if (this.tokenSet[which]) return common.t('A token is set. Type a new one only to replace it.');
		return which === 'relay'
			? common.t('Not set yet: paste the token the relay showed when you added this router.')
			: common.t('Not set yet: paste the token of the tunnel you created in the Cloudflare dashboard.');
	},

	/* Why «Enabled» in this section cannot be saved as the form stands, or null.
	 * A Cloudflare tick saved earlier (v1.16.0 took one without cloudflared) is
	 * not judged again while it is left alone — the service judges only what a
	 * Save sends, and the State line says what is wrong with it. LuCI hands a
	 * Flag's validator the input's value ("1") ticked or not, so the tick is
	 * read here, never taken from that argument. */
	enableProblem: function (sid) {
		var o = this.opts && this.opts[sid];
		if (!this.rendered || !o || !o.enabled) return null;
		var on = formOf(o.enabled, sid) === '1';
		var typed = !!formOf(o.token, sid);
		if (sid === 'relay')
			return common.relayEnableProblem(on, formOf(o.relayUrl, sid), typed || this.tokenSet.relay);
		if (this.loaded.cloudflared.enabled && !typed) return null;
		return common.cloudflaredEnableProblem(on, this.cfInstalled, typed || this.tokenSet.cloudflared);
	},

	/* Judge the tick again — after the URL or a token was typed, or cloudflared
	 * came in — so LuCI's red mark on it follows the form. */
	recheck: function (sid) {
		var f = this.opts && this.opts[sid] && this.opts[sid].enabled;
		if (this.rendered && f && typeof f.triggerValidation === 'function') f.triggerValidation(sid);
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
				common.t('Not installed'),
				this.installError ? ' — ' + common.t('Install failed: %s', this.installError) : '',
				' ',
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, 'handleInstall') }, [ common.t('Install') ])
			]);
		}
	},

	refresh: function () {
		var self = this, seq = ++this.pollSeq;
		return common.remoteStatus().then(function (st) { self.applyState(st, seq); }, function () { self.applyState(null, seq); });
	},

	applyState: function (st, seq) {
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
		// the last line of its log — unless the phrase already ends with it as the reason it is not running
		el.cfState.textContent = common.cloudflaredText(c) + (c.installed && c.lastLine && (c.running || !c.enabled) ? ' — ' + c.lastLine : '');
		this.followInstall(c, seq || 0);
	},

	/* The install's progress, from status reads that left after Install was
	 * accepted (one already on its way shows the time before the click):
	 * installing until the service's install ends — installed, or failed with
	 * its reason and Install offered again. It used to wait for "installed"
	 * only, and a failed opkg left «در حال نصب…» on the page for good (L6). */
	followInstall: function (c, seq) {
		if (c.installed) {
			if (!this.cfInstalled) {
				this.cfInstalled = true;
				this.installing = false;
				this.installError = null;
				this.showInstalled();
				this.recheck('cloudflared');
				common.notify(common.t('cloudflared is installed.'));
			}
			return;
		}
		if (seq <= this.installAfter) return;
		if (c.installing) {
			if (!this.installing) { this.installing = true; this.showInstalled(); }
			return;
		}
		var failed = (c.lastInstall && c.lastInstall.ok === false) ? String(c.lastInstall.error || '?') : null;
		if (this.installing) {
			this.installing = false;
			this.installError = failed;
			this.showInstalled();
			if (failed) common.notify(common.t('Install failed: %s', failed), 'danger');
		}
		else if (failed !== this.installError) {
			this.installError = failed;
			this.showInstalled();
		}
	},

	handleInstall: function () {
		var self = this;
		return common.cloudflaredInstall().then(function (r) {
			var err = common.errorOf(r);
			if (err) return common.notify(err, 'danger');
			self.installing = true;
			self.installError = null;
			self.installAfter = self.pollSeq;
			self.showInstalled();
		}, common.failed);
	},

	handleSave: function () {
		var self = this, m = this.map;
		if (!m) return Promise.resolve();
		// the page's own check first, with the reason in words (LuCI's refusal of
		// an invalid field says only "invalid input value" on 23.05)
		this.recheck('relay');
		this.recheck('cloudflared');
		var problem = this.enableProblem('relay') || this.enableProblem('cloudflared');
		if (problem) {
			common.showRefusal(problem);
			return Promise.reject(new Error(problem));
		}
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
					common.showRefusal(err);
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
				common.showRefusal(common.rpcError(e));
				throw e;
			});
		});
	},

	handleSaveApply: null
});
