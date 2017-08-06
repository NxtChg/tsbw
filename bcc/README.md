## The Simplest Bitcoin Wallet (Bitcoin Cash version)

Online Bitcoin wallets often have one or two annoying idiosyncrasies, like demanding mandatory 2-FA, and there's nothing you can do about it.

It's also not clear what information they collect. Besides, sometimes you just need a simple wallet.

So I made The Simplest Bitcoin Wallet :)

http://simcoin.info/tsbw/bcc/

Mostly for myself, but maybe somebody will find it useful too.

Please help test it, if you have a spare minute.

If you like it, send some love here: 19BryCNdGs5F48J6yvw41pVSd5RDiA4j1x.

----

The code is based on [coinb.in](https://github.com/OutCast3k/coinbin): I removed 3/4 of it, fixed a few bugs and rewrote the rest. It is now easier to read and verify.

It's also a good start if you are interested to learn about Bitcoin and JS wallets since it's a lot simpler than the original.

Usage example:
```
var tx = btc.new_tx();

tx.add_input ('01020304abcdef', 0, '76a9141d8f0476ea05d9459e004fd0ff10588dd3979e6788ac', 0.01); // txid, no, script
tx.add_output('13nwZVh9RsKuZGegVn5KWHM51dA98Mho5f', 1.2); // address, amount

var keys = btc.get_keys('123'); // 123 = passphrase

var signed = tx.sign(keys); console.log(signed);
```

Nothing is sent to my server, everything is done in the browser. It gets utxo and sends signed txs via external API's.

All API access is wrapped in a "backend" object, which can be easily swapped. I wrote two: for blochchain.info and blockexplorer.com.

You can enter a compressed WIF key as your passphrase; this means you can use the same wallets you have at https://coinb.in or any other wallet that allows exporting in this format.
