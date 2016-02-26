/*=============================================================================
  Created by NxtChg (admin@nxtchg.com), 2016. License: Public Domain.
=============================================================================*/

// based on CryptoJS (code.google.com/p/crypto-js) by Jeff Mott

function   to_utf8(s){ return unescape(encodeURIComponent(s)); }
function from_utf8(s){ return decodeURIComponent(escape  (s)); }
//_____________________________________________________________________________

function words2bin(words)
{
	for(var bytes = [], i = 0; i < words.length * 32; i += 8)
	{
		bytes.push((words[i>>>5] >>> (24 - i % 32)) & 0xFF);
	}
	return bytes;
}//____________________________________________________________________________

function bin2words(bytes)
{
	for(var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
	{
		words[b>>>5] |= (bytes[i] & 0xFF) << (24 - b % 32);
	}
	return words;
}//____________________________________________________________________________

function str2bin(str)
{
	for(var bytes = [], i = 0; i < str.length; i++)
	{
		bytes.push(str.charCodeAt(i) & 0xFF);
	}
	return bytes;
};//___________________________________________________________________________

/*function bin2str(bytes)
{
	for(var str = [], i = 0; i < bytes.length; i++)
	{
		str.push(String.fromCharCode(bytes[i]));
	}
	return str.join("");
};//___________________________________________________________________________
*/

function SHA256(msg)
{
 var K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
          0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
          0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
          0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
          0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
          0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
          0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
          0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2];

	// Convert to byte array
	if(msg.constructor == String) msg = str2bin(to_utf8(msg)); // else assume byte array already

	var m = bin2words(msg),
	    l = msg.length * 8,
	    H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19],
	    w = [], a, b, c, d, e, f, g, h, i, j, t1, t2;

	// Padding
	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >> 9) << 4) + 15] = l;

	for(var i = 0; i < m.length; i += 16)
	{
		a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];

		for(var j = 0; j < 64; j++)
		{
			if(j < 16) w[j] = m[j+i];
			else
			{
				var gamma0x = w[j-15],
				    gamma1x = w[j- 2],
				    gamma0  = ((gamma0x << 25) | (gamma0x >>>  7)) ^ ((gamma0x << 14) | (gamma0x >>> 18)) ^ (gamma0x >>>  3),
				    gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^ ((gamma1x << 13) | (gamma1x >>> 19)) ^ (gamma1x >>> 10);

				w[j] = gamma0 + (w[j-7] >>> 0) + gamma1 + (w[j-16] >>> 0);
			}

			var ch  = e & f ^ ~e & g,
			    maj = a & b ^ a & c ^ b & c,
			    sigma0 = ((a << 30) | (a >>>  2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22)),
			    sigma1 = ((e << 26) | (e >>>  6)) ^ ((e << 21) | (e >>> 11)) ^ ((e <<  7) | (e >>> 25));

			t1 = (h >>> 0) + sigma1 + ch + (K[j]) + (w[j] >>> 0);
			t2 = sigma0 + maj;

			h = g; g = f; f = e; e = ( d + t1) >>> 0;
			d = c; c = b; b = a; a = (t1 + t2) >>> 0;

		}

		H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
	}

	return words2bin(H);
}//____________________________________________________________________________

function SHA256_HMAC(msg, key)
{
	var o_key = [], i_key = [];

	// Convert to byte arrays
	if(msg.constructor == String) msg = str2bin(to_utf8(msg));
	if(key.constructor == String) key = str2bin(to_utf8(key));
	// else, assume byte arrays already
    
	if(key.length > 16 * 4) key = SHA256(key); // allow arbitrary length keys
    
	for(var i = 0; i < 16 * 4; i++)
	{
		o_key[i] = key[i] ^ 0x5C;
		i_key[i] = key[i] ^ 0x36;
	}

	return SHA256(o_key.concat(SHA256(i_key.concat(msg))));
}//____________________________________________________________________________

var zl = [
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
    3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
    1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
    4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13];
var zr = [
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11];
var sl = [
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ];
var sr = [
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ];

var hl = [ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
var hr = [ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

function f1(x, y, z){ return ((x) ^ (y) ^ (z)); }
function f2(x, y, z){ return (((x)&(y)) | ((~x)&(z))); }
function f3(x, y, z){ return (((x) | (~(y))) ^ (z)); }
function f4(x, y, z){ return (((x) & (z)) | ((y)&(~(z)))); }
function f5(x, y, z){ return ( (x) ^ ((y) |(~(z)))); }

function rotl(x,n){ return (x<<n) | (x>>>(32-n)); }

var ripemd160_block = function (H, M, offset)
{
  // Swap endian
  for(var i = 0; i < 16; i++)
  {
    var offset_i = offset + i;
    var M_offset_i = M[offset_i];

    // Swap
    M[offset_i] = (
        (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
        (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
    );
  }

  // Working variables
  var al, bl, cl, dl, el;
  var ar, br, cr, dr, er;

  ar = al = H[0]; br = bl = H[1];
  cr = cl = H[2]; dr = dl = H[3];
  er = el = H[4];

  for(var t, i = 0; i < 80; i += 1)
  {
    t = (al +  M[offset+zl[i]])|0;
    if(i < 16) t += f1(bl,cl,dl) + hl[0]; else
    if(i < 32) t += f2(bl,cl,dl) + hl[1]; else
    if(i < 48) t += f3(bl,cl,dl) + hl[2]; else
    if(i < 64) t += f4(bl,cl,dl) + hl[3];
    else       t += f5(bl,cl,dl) + hl[4]; // if (i<80)

    t = t|0;
    t =  rotl(t,sl[i]);
    t = (t+el)|0;
    al = el;
    el = dl;
    dl = rotl(cl, 10);
    cl = bl;
    bl = t;

    t = (ar + M[offset+zr[i]])|0;
    if(i < 16) t += f5(br,cr,dr) + hr[0]; else
    if(i < 32) t += f4(br,cr,dr) + hr[1]; else
    if(i < 48) t += f3(br,cr,dr) + hr[2]; else
    if(i < 64) t += f2(br,cr,dr) + hr[3];
    else       t += f1(br,cr,dr) + hr[4]; // if (i<80)
    
    t = t|0;
    t = rotl(t,sr[i]);
    t = (t+er)|0;
    ar = er;
    er = dr;
    dr = rotl(cr, 10);
    cr = br;
    br = t;
  }
  // Intermediate hash value
  t    = (H[1] + cl + dr)|0;
  H[1] = (H[2] + dl + er)|0;
  H[2] = (H[3] + el + ar)|0;
  H[3] = (H[4] + al + br)|0;
  H[4] = (H[0] + bl + cr)|0;
  H[0] =  t;
};//___________________________________________________________________________

function RIPEMD160(msg)
{
	var H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
	
	var m = bin2words(msg);
	
	var nBitsLeft  = msg.length * 8;
	var nBitsTotal = msg.length * 8;
	
	// Add padding
	m[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	m[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	(((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
	(((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
	);
	
	for(var i = 0; i < m.length; i += 16){ ripemd160_block(H, m, i); }
	
	// Swap endian
	for(var i = 0; i < 5; i++)
	{
		var H_i = H[i]; // Shortcut
		
		H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) | (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	}
	
	return words2bin(H);
}
