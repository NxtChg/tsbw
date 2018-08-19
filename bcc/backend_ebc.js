/*=============================================================================
  Created by NxtChg (admin@nxtchg.com), 2016-2017. License: Public Domain.
=============================================================================*/

// Back-end for explorer.bitcoin.com API

var backend =
{
	host:      'explorer.bitcoin.com',
	home_page: 'https://explorer.bitcoin.com/bch/',
	adr_page:  'https://explorer.bitcoin.com/bch/address/',
	tx_page:   'https://explorer.bitcoin.com/bch/tx/'
};//___________________________________________________________________________

function backend_balance_cb(data)
{
	console.log(data);
	
	try{ data = JSON.parse(data); } catch(e){ data = {}; }
	
	this.balance_cb(parseFloat(data.balance) + parseFloat(data.unconfirmedBalance));
}//____________________________________________________________________________

function backend_unspent_cb(data)
{
	var utxo = false; console.log(data);

	try{ data = JSON.parse(data); } catch(e){ data = {}; }

	if(data.length)
	{
		utxo = [];
	                               
		for(var i = 0; i < data.length; i++)
		{
			var u = data[i];

			utxo.push({txid: u.txid, n: u.vout, amount: u.satoshis, script: u.scriptPubKey});
		}
	}

	backend.unspent_cb(utxo);
}//____________________________________________________________________________

function backend_send_cb(data)
{
	console.log(data);

	var m = /^[\s\"]*[0-9a-f]{64}[\s\"]*$/.test(data); // check if this is txid

	backend.send_cb(m ? '' : data);
}//____________________________________________________________________________

backend.get_balance = function(adr, cb)
{
	this.balance_cb = cb;
	
	js.ajax('GET', 'https://rest.bitcoin.com/v1/address/details/' + adr, '', backend_balance_cb);
};//___________________________________________________________________________

backend.get_utxo = function(adr, cb)
{
	this.unspent_cb = cb;
	
	js.ajax('GET', 'https://rest.bitcoin.com/v1/address/utxo/' + adr, '', backend_unspent_cb);
};//___________________________________________________________________________

backend.send = function(tx, cb)
{
	this.send_cb = cb;

	js.ajax('POST', 'https://rest.bitcoin.com/v1/rawtransactions/sendRawTransaction/' + tx, '', backend_send_cb); // this blunder should be fixed in v2 of the API
};//___________________________________________________________________________
