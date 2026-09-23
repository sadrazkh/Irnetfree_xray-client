'use strict';
'require view';
'require fs';
'require uci';

// The one job of this page: hand the operator the link to the IRNetFree UI
// with the token this router generated — the token file is root-only and
// this page sits behind LuCI's own login. Nothing here changes anything.
return view.extend({
	load: function () {
		return Promise.all([
			fs.read('/etc/irnetfree/token').catch(function () { return ''; }),
			uci.load('irnetfree')
		]);
	},
	render: function (data) {
		var token = (data[0] || '').trim();
		var port = uci.get('irnetfree', 'main', 'port') || '6969';
		var url = 'http://' + window.location.hostname + ':' + port + '/' + (token ? '?token=' + encodeURIComponent(token) : '');
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'IRNetFree'),
			E('p', {}, 'The tunnel for every device behind this router. Its own page runs on port ' + port + '; the button opens it with the access token this router generated.'),
			E('p', {}, E('a', { 'class': 'btn cbi-button cbi-button-apply', 'href': url, 'target': '_blank', 'rel': 'noopener' }, 'Open IRNetFree')),
			token ? '' : E('p', { 'class': 'alert-message warning' }, 'No token yet: start the service (/etc/init.d/irnetfree start) and reload this page.')
		]);
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
