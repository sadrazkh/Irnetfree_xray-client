'use strict';
'require view';
'require dom';
'require ui';
'require irnetfree.common as common';

/*
 * Services → IRNetFree → Log: the service's own log (its in-memory ring, the
 * last 300 lines), Refresh, and Copy diagnostics — the status, versions,
 * memory, routing rules and the same lines in one block for a bug report, with
 * tokens and passwords left out by the service. Copying falls back to a dialog
 * with the text selected where the browser refuses (plain-http LuCI is not a
 * "secure context", so the async clipboard is usually not there).
 */

var LINES = 300;

return view.extend({
	load: function () {
		return common.log(LINES);
	},

	render: function (res) {
		this.problem = E('div', {});
		this.pre = E('pre', {
			'id': 'irnf-log',
			'dir': 'ltr',
			'style': 'white-space:pre-wrap;word-break:break-all;max-height:70vh;overflow:auto;text-align:left;font-size:12px'
		});
		this.show(res);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ common.t('IRNetFree log') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ common.t('The service’s last 300 lines, newest at the bottom.') ]),
			this.problem,
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'style': 'margin-bottom:.5em' }, [
					E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, 'handleRefresh') }, [ common.t('Refresh') ]), ' ',
					E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, 'handleCopy') }, [ common.t('Copy diagnostics') ])
				]),
				E('p', {}, [ common.t('Copy diagnostics puts the status, versions, memory, routing rules and these lines on the clipboard for a bug report — tokens and passwords are left out.') ]),
				this.pre
			])
		]);
	},

	show: function (res) {
		var self = this;
		var err = common.errorOf(res);
		dom.content(this.problem, err ? [ common.problemBox(res, function () { return self.handleRefresh(); }) ] : null);
		var lines = (!err && Array.isArray(res.lines)) ? res.lines : [];
		dom.content(this.pre, [ err ? '' : (lines.length ? lines.join('\n') : common.t('The log is empty.')) ]);
		this.pre.scrollTop = this.pre.scrollHeight;
	},

	handleRefresh: function () {
		var self = this;
		return common.log(LINES).then(function (res) { self.show(res); });
	},

	handleCopy: function () {
		return common.diagnostics().then(function (res) {
			var err = common.errorOf(res);
			if (err) return common.notify(err, 'danger');
			var text = String(res.text || '');
			return common.copyText(text).then(function (ok) {
				if (ok) common.notify(common.t('Diagnostics copied to the clipboard.'));
				else common.showText(common.t('Copy diagnostics'), text);
			});
		});
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
