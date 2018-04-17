/*=============================================================================
  Created by NxtChg (admin@nxtchg.com), 2016. License: Public Domain.
=============================================================================*/

var js = {};
//_____________________________________________________________________________

js.trim  = function(str){ return (str || '').replace(/(^\s+)|(\s+$)/g, ''); };
//_____________________________________________________________________________

window.$ = function(name){ return document.getElementById(name); };
//_____________________________________________________________________________

function log(msg){ console.log(msg); }
//_____________________________________________________________________________

Element.prototype.show = function(type){ this.style.display = (type || 'block'); };
Element.prototype.hide = function(    ){ this.style.display = 'none'; };
//_____________________________________________________________________________

js.enable_form = function(name, yes)
{
	var es = $(name).elements;

	for(var i = 0; i < es.length; i++)
	{
		if(es[i].tagName == 'INPUT' || es[i].tagName == 'BUTTON') es[i].disabled = !yes;
	}
};//___________________________________________________________________________

js.format_money = function(n, m, no_trim)
{
	n = parseFloat(n).toFixed(m||0);

	var r = n.split('.'); if(r.length == 1) r[1] = '';

	r[0] = r[0].replace(/(\d)(?=(\d{3})+$)/g, '$1,');
	if(!no_trim)
	r[1] = r[1].replace(/0+$/g, '');

	return r[0] + (r[1] != '' ? '.' + r[1] : '');
};//___________________________________________________________________________

js.ajax = function(method, url, data, cb)
{
	var http = new XMLHttpRequest;

	if(method == 'GET')
	{
		if(data.length) url += (url.indexOf('?') < 0 ? '?' : '&') + data;
		
		data = null;
	}

	http.open(method, url, true);
	
	http.onreadystatechange = function(){ if(http.readyState == 4 && cb) cb(http.responseText);	};

	if(method == 'POST'){ http.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded'); }

	http.send(data);
};//___________________________________________________________________________
