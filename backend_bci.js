/*=============================================================================
  Created by NxtChg (admin@nxtchg.com), 2016-2018. License: Public Domain.
=============================================================================*/

// Back-end for blockchain.info API

var backend =
{
	host:      'blockchain.info',
	home_page: 'https://blockchain.info/',
	adr_page:  'https://blockchain.info/address/',
	tx_page:   'https://blockchain.info/tx/'
};//___________________________________________________________________________

function backend_balance_cb(res)
{
	console.log(res); this.balance_cb(parseFloat(res) / 1e8);
}//____________________________________________________________________________

function backend_unspent_cb(data)
{
	var utxo = false; console.log(data);

	try{ data = JSON.parse(data); } catch(e){ data = {}; }

	if(typeof data.unspent_outputs != 'undefined')
	{
		var u = data.unspent_outputs; utxo = [];
	                               
		for(var i = 0; i < u.length; i++)
		{
			utxo.push({txid: u[i].tx_hash_big_endian, n: u[i].tx_output_n, amount: u[i].value, script: u[i].script});
		}
	}

	backend.unspent_cb(utxo);
}//____________________________________________________________________________

function backend_send_cb(res)
{
	console.log(res);

	backend.send_cb(res.indexOf('Transaction Submitted') == 0 ? '' : res);
}//____________________________________________________________________________

backend.get_balance = function(adr, cb)
{
	this.balance_cb = cb;
	
	js.ajax('GET', 'https://blockchain.info/q/addressbalance/' + adr, 'cors=true', backend_balance_cb);
};//___________________________________________________________________________

backend.get_utxo = function(adr, cb)
{
	this.unspent_cb = cb;
	
	js.ajax('GET', 'https://blockchain.info/unspent?active=' + adr, 'cors=true', backend_unspent_cb);
};//___________________________________________________________________________

backend.send = function(tx, cb)
{
	this.send_cb = cb;

	js.ajax('POST', 'https://blockchain.info/pushtx', 'tx=' + tx, backend_send_cb);
};//___________________________________________________________________________
