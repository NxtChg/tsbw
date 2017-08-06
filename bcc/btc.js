/*=============================================================================
  Created by NxtChg (admin@nxtchg.com), 2016-2017. License: Public Domain.
=============================================================================*/

// Based on coinb.in code by OutCast3k.

var btc = { };

btc.bin2hex = function(b)
{
	for(var h = [], i = 0; i < b.length; i++)
	{
		h.push((b[i]>>> 4).toString(16));
		h.push((b[i] & 15).toString(16));
	}
	
	return h.join('');
};//___________________________________________________________________________

btc.hex2bin = function(h)
{
	for(var b = [], i = 0; i < h.length; i += 2)
	{
		b.push(parseInt(h.substr(i,2), 16));
	}
	return b;
};//___________________________________________________________________________

btc.n2bytes = function(num, bytes) // little-endian
{
	var r = [];
	
	for(var i = 0; i < bytes; i++){ r[i] = (num % 256); num = Math.floor(num / 256); }

	return r;
};//___________________________________________________________________________

btc.n2vint = function(num)
{
	if(num <        253) return [num];
	if(num <      65536) return [253].concat(btc.n2bytes(num, 2));
	if(num < 4294967296) return [254].concat(btc.n2bytes(num, 4));
	else                 return [255].concat(btc.n2bytes(num, 8));
};//___________________________________________________________________________

btc.base58_encode = function(bytes)
{
	var alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	var str = [], bi = BigInteger.fromByteArrayUnsigned(bytes), base = BigInteger.valueOf(58);

	while(bi.compareTo(base) >= 0)
	{
		var mod = bi.mod(base);
		
		str.unshift(alphabet[mod.intValue()]);

		bi = bi.subtract(mod).divide(base);
	}

	str.unshift(alphabet[bi.intValue()]);

	for(var i = 0; i < bytes.length; i++)
	{
		if(bytes[i] == 0) str.unshift('1'); else break;
	}

	return str.join('');
};//___________________________________________________________________________

btc.base58_decode = function(str)
{
	var alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	var bi = BigInteger.valueOf(0), base = BigInteger.valueOf(58), zeros_cnt = 0;

	for(var i = str.length - 1; i >= 0; i--)
	{
		var idx = alphabet.indexOf(str[i]); if(idx < 0){ throw "Invalid character"; }

		bi = bi.add(BigInteger.valueOf(idx).multiply(base.pow(str.length - 1 - i)));
	
		if(str[i] == '1') zeros_cnt++; else zeros_cnt = 0;
	}
	
	var bytes = bi.toByteArrayUnsigned();

	while(zeros_cnt-- > 0) bytes.unshift(0);

	return bytes;
};//___________________________________________________________________________

btc.new_pk = function(sk) // Generate a public key from a private key.
{
	var sk_bigint = BigInteger.fromByteArrayUnsigned(sk);
	var curve = EllipticCurve.getSECCurveByName("secp256k1");
	
	var p = curve.getG().multiply(sk_bigint);
	var x = p.getX().toBigInteger();
	var y = p.getY().toBigInteger();
	
	var compressed = [y.isEven() ? 0x02 : 0x03].concat(EllipticCurve.integerToBytes(x,32));
	
	return btc.bin2hex(compressed);
};//___________________________________________________________________________

btc.pk2adr = function(pk, is_script_hash)
{
	var r = btc.hex2bin(pk);
	
	if(!is_script_hash) r = RIPEMD160(SHA256(r));

	r.unshift(0x00);

	var checksum = SHAx2(r).slice(0, 4);

	return this.base58_encode(r.concat(checksum));
};//___________________________________________________________________________

btc.sk2wif = function(sk)
{
	var r = [0x80].concat(sk, [0x01]);

	var checksum = SHAx2(r).slice(0,4);

	return this.base58_encode(r.concat(checksum));
};//___________________________________________________________________________

btc.wif2sk = function(wif)
{
	var key = this.base58_decode(wif);

	// shouldn't we check the checksum here?
	// or do we always call decode_adr first?

	if(key.length < 34+4 && key[key.length-5] != 0x01)
	{
		throw 'only compressed keys are supported';
	}

	return key.slice(1, key.length-5);
};//___________________________________________________________________________

btc.decode_adr = function(adr)
{
	try
	{
		var bytes = btc.base58_decode(adr);
		var front = bytes.slice(0, bytes.length-4);
		var back  = bytes.slice(   bytes.length-4);

		var checksum = SHAx2(front).slice(0, 4);

		if(checksum + '' != back + '') return false;

		var a = { version: front[0], type:'', bytes: front.slice(1) };

		switch(a.version)
		{
			case 0x00: a.type = 'standard'; return a;
			case 0x05: a.type = 'multisig'; return a;
			case 0x80: a.type = 'wifkey';   return a;
		}
	}
	catch(e){ }

	return false;
};//___________________________________________________________________________

btc.extend = function(pass)
{
	pass = SHA256('tsbw'+pass+'magic');
	
	for(var i = 0; i < 40; i++){ pass = pass.concat(SHA256(pass), RIPEMD160(pass)).reverse(); }

	return SHA256(pass);
};//___________________________________________________________________________

// Generate a private and public keypair, with address and WIF address.

btc.get_keys = function(pass)
{
	var adr = this.decode_adr(pass);
    
    var sk = (adr && adr.type == 'wifkey' ? this.wif2sk(pass) : this.extend(pass));

	var pk = this.new_pk(sk);

	return { 'sk': sk, 'pk': pk, 'adr': this.pk2adr(pk), 'wif': this.sk2wif(sk) };
};//___________________________________________________________________________

///////////////////////////////////////////////////////////////////////////////
// Script
///////////////////////////////////////////////////////////////////////////////

btc.new_script = function(data)
{
	data = data || ''; if(typeof data != 'string') throw 'new_script() needs a string'; //s.buffer = data;

	var s = { buffer: btc.hex2bin(data) };
    
	s.write_opcode = function(op){ this.buffer.push(op); this.chunks.push(op); return true; };

	s.write_bytes = function(data) // we will probably ever need OP_PUSHDATA1 only...
	{
		if(data.length < 76)
		{
			this.buffer.push(data.length);
		}
		else if(data.length <= 0xFF)
		{
			this.buffer.push(76); //OP_PUSHDATA1
			this.buffer.push(data.length);
		}
		else if(data.length <= 0xffff)
		{
			this.buffer.push(77); //OP_PUSHDATA2
			this.buffer.push((data.length      ) & 0xFF);
			this.buffer.push((data.length >>> 8) & 0xFF);
		}
		else
		{
			this.buffer.push(78); //OP_PUSHDATA4
			this.buffer.push((data.length       ) & 0xFF);
			this.buffer.push((data.length >>>  8) & 0xFF);
			this.buffer.push((data.length >>> 16) & 0xFF);
			this.buffer.push((data.length >>> 24) & 0xFF);
		}

		this.buffer = this.buffer.concat(data); this.chunks.push(data);

		return true;
	};//_______________________________________________________________________

	s.spend_to_script = function(adr)
	{
		var sc = btc.new_script();

		adr = btc.decode_adr(adr);

		if(adr.version == 5) // multisig address
		{
			sc.write_opcode(169); //OP_HASH160
			sc.write_bytes (adr.bytes);
			sc.write_opcode(135); //OP_EQUAL
		}
		else // regular address
		{
			sc.write_opcode(118); //OP_DUP
			sc.write_opcode(169); //OP_HASH160
			sc.write_bytes (adr.bytes);
			sc.write_opcode(136); //OP_EQUALVERIFY
			sc.write_opcode(172); //OP_CHECKSIG
		}

		return sc;
	};//_______________________________________________________________________

	s.parse = function()
	{
		s.chunks = [];
		
		for(var i = 0; i < this.buffer.length; )
		{
			var opcode = this.buffer[i++];

			if(opcode >= 0xF0){	opcode = (opcode << 8) | this.buffer[i++]; }
		     
		    if(opcode > 78){ this.chunks.push(opcode); }
		    else
    	    {
    	    	var len;

    	    	if(opcode <  76){ len = opcode; }
    	    	if(opcode >= 76){ len =              this.buffer[i++]; } // OP_PUSHDATA1
    	    	if(opcode >= 77){ len = (len << 8) | this.buffer[i++]; } // OP_PUSHDATA2
    	    	if(opcode >= 78){ len = (len << 8) | this.buffer[i++];   // OP_PUSHDATA4
				                  len = (len << 8) | this.buffer[i++]; }

				this.chunks.push(this.buffer.slice(i, i + len)); i += len; // read_chunk(len);

				if(len < 0) break; // return false; ?
    	    }
		}
		
		return true; // No validity checks here?
	};//_______________________________________________________________________

	s.parse();

	return s;
};//___________________________________________________________________________

///////////////////////////////////////////////////////////////////////////////
// Transaction
///////////////////////////////////////////////////////////////////////////////

btc.new_tx = function()
{
	var tx = { amount:0, ins:[], outs:[], ts:null, block:null };

	tx.add_input = function(txid, idx, script, amount)
	{
		var o = { outpoint:{ 'hash':txid, 'index':idx }, sequence:4294967295 };
		
		if(amount) o.value = new BigInteger('' + Math.round((amount * 1) * 1e8), 10);

		o.script = btc.new_script(script || '');

		return this.ins.push(o);
	};//_______________________________________________________________________

	tx.add_output = function(address, amount)
	{
		var o = {}; this.amount += amount * 1;

		o.value = new BigInteger('' + Math.round((amount * 1) * 1e8), 10);
		
		o.script = btc.new_script().spend_to_script(address);
	
		return this.outs.push(o);
	};//_______________________________________________________________________

	tx.add_unspent = function(u) // [ {txid:'01ab23cc...', n:0, amount:99999, script:'76a914...'}, {...} ]
	{
		var total = 0;
		                               
		for(var i = 0; i < u.length; i++)
		{
			if(u[i].script.indexOf('76a914') != 0) continue; // only pay-to-pkhash

			this.add_input(u[i].txid, u[i].n, u[i].script, u[i].amount / 1e8);

			total += u[i].amount * 1;
		}

		return (total / 1e8); // amount is in satoshis
	};//_______________________________________________________________________

	tx.transaction_hash = function(idx) // not txid!
	{
		var b = this.serialize(idx).concat(btc.n2bytes(0x01 | 0x40, 4)); // signature type: 0x40 = SIGHASH_FORKID for BCC

		return SHAx2(b);
	};//_______________________________________________________________________

	// bad_rs is used only if the k resulted in bad r or s

	tx.deterministic_K = function(sk, hash, bad_rs) // https://tools.ietf.org/html/rfc6979#section-3.2
	{
		// if r or s were invalid when this function was used in signing,
		// we do not want to actually compute r, s here for efficiency, so,
		// we can increment bad_rs. Explained at the end of RFC 6979 section 3.2

		// Step: a -> hash is a byteArray of the message digest. so h1 == hash in our case

		var curve = EllipticCurve.getSECCurveByName("secp256k1"), N = curve.getN();

		var v = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]; // Step: b
		var k = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]; // Step: c

		k = SHA256_HMAC(v.concat([0], sk, hash), k); // Step: d
		v = SHA256_HMAC(v,                       k); // Step: e
		k = SHA256_HMAC(v.concat([1], sk, hash), k); // Step: f
		v = SHA256_HMAC(v,                       k); // Step: g
		v = SHA256_HMAC(v,                       k); // Step: h1,2:

		var KBigInt = BigInteger.fromByteArrayUnsigned(v); // Step h3: (since we know tlen == qlen, just copy v to T)

		// loop if KBigInt is not in the range of [1, N-1] or if bad_rs needs incrementing
		for(var i = 0; KBigInt.compareTo(N) >= 0 || KBigInt.compareTo(BigInteger.ZERO) <= 0 || i < bad_rs; i++)
		{
			k = SHA256_HMAC(v.concat([0]), k);
			v = SHA256_HMAC(v, k);
			v = SHA256_HMAC(v, k);
			
			KBigInt = BigInteger.fromByteArrayUnsigned(v);
		};

		return KBigInt;
	};//_______________________________________________________________________

	tx.sign_input = function(idx, sk)
	{
		function serialize_sig(r, s)
		{
			r = r.toByteArraySigned();
			s = s.toByteArraySigned();

			var len = r.length + s.length + 4;

			return [0x30, len, 0x02, r.length].concat(r, [0x02, s.length], s);
		}

		var hash   = this.transaction_hash(idx);
		var priv   = BigInteger.fromByteArrayUnsigned(sk);
		var curve  = EllipticCurve.getSECCurveByName("secp256k1");
		var n      = curve.getN();
		var e      = BigInteger.fromByteArrayUnsigned(hash);
		var bad_rs = 0;

		do
		{
			var k = this.deterministic_K(sk, hash, bad_rs);
			var G = curve.getG();
			var Q = G.multiply(k);
			var r = Q.getX().toBigInteger().mod(n);
			var s = k.modInverse(n).multiply(e.add(priv.multiply(r))).mod(n);
			bad_rs++;
		}
		while(r.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(BigInteger.ZERO) <= 0);

		var half_n = n.shiftRight(1); if(s.compareTo(half_n) > 0) s = n.subtract(s); // Force lower s values per BIP62

		return serialize_sig(r,s).concat([1 | 0x40]); // Bitcoin Cash type
	};//_______________________________________________________________________

	tx.sign = function(keys) // replaces tx inputs!
	{
		for(var i = 0; i < this.ins.length; i++) // sign inputs
		{
			var s = btc.new_script();

			s.write_bytes(this.sign_input(i, keys.sk));
			s.write_bytes(btc.hex2bin(keys.pk));

			this.ins[i].script = s;
		}

		console.log('TXID: '+tx.txid(), 'TX: '+btc.bin2hex(this.serialize()));

		return btc.bin2hex(this.serialize());
	};//_______________________________________________________________________

	tx._get_prevouts = function()
	{
		var b = [];

		for(var i = 0; i < this.ins.length; i++)
		{
			var t = this.ins[i];

			b = b.concat(btc.hex2bin(t.outpoint.hash).reverse());
			b = b.concat(btc.n2bytes(t.outpoint.index, 4));
		}

		return b;
	};//__________________________________________________________________________
	
	tx._get_sequences = function()
	{
		var b = [];

		for(var i = 0; i < this.ins.length; i++)
		{
			b = b.concat(btc.n2bytes(this.ins[i].sequence, 4));
		}

		return b;
	};//__________________________________________________________________________
	
	tx._get_outputs = function()
	{
		var b = [];

		for(var i = 0; i < this.outs.length; i++)
		{
			var t = this.outs[i];

			b = b.concat(btc.n2bytes(t.value, 8));

			b = b.concat(btc.n2vint(t.script.buffer.length), t.script.buffer);
		}

		return b;
	};//__________________________________________________________________________

	tx.serialize = function(idx) // 'idx' is only used internally to get tx hash
	{
		var b = btc.n2bytes(1, 4); // version

		if(idx == undefined)
		{
			b = b.concat(btc.n2vint(this.ins.length));
	
			for(var i = 0; i < this.ins.length; i++)
			{
				var t = this.ins[i];
	
				b = b.concat(btc.hex2bin(t.outpoint.hash).reverse(), btc.n2bytes(t.outpoint.index, 4));
				b = b.concat(btc.n2vint(t.script.buffer.length), t.script.buffer);
				b = b.concat(btc.n2bytes(t.sequence, 4));
			}
	
			b = b.concat(btc.n2vint(this.outs.length));
	
			for(var i = 0; i < this.outs.length; i++)
			{
				var t = this.outs[i];
				
				b = b.concat(btc.n2bytes(t.value, 8), btc.n2vint(t.script.buffer.length), t.script.buffer);
			}
		}
		else // serialization for transaction hash
		{
			var t = this.ins[idx];

			b = b.concat(SHAx2(this._get_prevouts()));
			b = b.concat(SHAx2(this._get_sequences()));
	
			b = b.concat(btc.hex2bin(t.outpoint.hash).reverse(), btc.n2bytes(t.outpoint.index, 4));
			b = b.concat(btc.n2vint(t.script.buffer.length), t.script.buffer);
			b = b.concat(btc.n2bytes(t.value,    8));
			b = b.concat(btc.n2bytes(t.sequence, 4));

			b = b.concat(SHAx2(this._get_outputs()));
		}

		b = b.concat(btc.n2bytes(0,4)); // lock time

		return b;
	};//_______________________________________________________________________

	tx.estimate_size = function()
	{
		var size = 4 + 1 + 1 + 4;
        
		size += this.ins.length  * (32 + 4 + 1 + (71+33) + 4);
		size += this.outs.length * ( 1 + 8 + 1 + 25);

		return size;
	};//_______________________________________________________________________

	tx.size = function(){ return this.serialize().length; };

	tx.txid = function(){ return btc.bin2hex(SHAx2(this.serialize()).reverse()); };

	return tx;
};//___________________________________________________________________________

/*
var test_tx = btc.new_tx();

test_tx.add_input ('01020304abcdef', 1, '76a9141d8f0476ea05d9459e004fd0ff10588dd3979e6788ac', 0.01);
test_tx.add_output('13nwZVh9RsKuZGegVn5KWHM51dA98Mho5f',  0.02);
test_tx.add_input ('99ff88ee77dd',   6, '76a9141d8f0476ea05d9459e004fd0ff10588dd3979e6788ac', 0.01);
test_tx.add_output('13hHvbAM89jEnZUK54g9i1RwskgRzWYBs1', 0.035);

var keys = btc.get_keys('L2oAXFV4KPzoVUCEWgot4qBRAQ4GEDBBPe28XXgPTfNykt1beVtV');

var signed = test_tx.sign(keys); console.log(signed);

if(signed != '0100000002efcdab04030201010000006b483045022100e9e3da64fe36dcac50632c1030d829bd713154536738ddcd66e138abbfd18629022077c82cde0966a6e96066798a46d240d04b5f15b62f79f9d1c43955643b89dafe012103be686ed7f0539affbaf634f3bcc2b235e8e220e7be57e9397ab1c14c39137eb4ffffffffdd77ee88ff99060000006a47304402203a61d63ccfb17017665b74d1b8873759e985aace9e91a1956beba861a33422b60220631a15205be57850bd07689e158cd9e1dc42eccb5bef694365ed604decf16aa9012103be686ed7f0539affbaf634f3bcc2b235e8e220e7be57e9397ab1c14c39137eb4ffffffff02009236bb1c0000001976a9141ea083b340bc01049f3589c72bf12dda600ff26988ac00bf7c48180900001976a9141d8f0476ea05d9459e004fd0ff10588dd3979e6788ac00000000')
{
	console.log("SIGNATURE FAILED!!!");
}
*/
