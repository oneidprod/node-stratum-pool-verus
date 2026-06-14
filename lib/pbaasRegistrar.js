var http = require('http');
var bignum = require('bignum');
var merkle = require('./merkleTree.js');
var util = require('./util.js');

// Assembles a minimal block hex from a PBaaS chain GBT response.
// verusd replaces nTime and nSolution internally, so placeholders are fine.
function assembleBlockHex(rpcData, nTimeOverride) {
    var coinbaseTx = rpcData.coinbasetxn ? rpcData.coinbasetxn.data : '';
    var coinbaseTxHash = rpcData.coinbasetxn
        ? util.reverseBuffer(Buffer.from(rpcData.coinbasetxn.hash, 'hex')).toString('hex')
        : '0000000000000000000000000000000000000000000000000000000000000000';

    var merkleRoot = merkle.getRoot(rpcData, coinbaseTxHash);
    var merkleRootReversed = util.reverseBuffer(Buffer.from(merkleRoot, 'hex')).toString('hex');
    var prevHashReversed = util.reverseBuffer(Buffer.from(rpcData.previousblockhash, 'hex')).toString('hex');
    var saplingRoot = rpcData.finalsaplingroothash
        ? util.reverseBuffer(Buffer.from(rpcData.finalsaplingroothash, 'hex')).toString('hex')
        : '0000000000000000000000000000000000000000000000000000000000000000';

    // 140-byte header: version(4) + prevhash(32) + merkleroot(32) + saplingroot(32) + time(4) + bits(4) + nonce(32)
    var header = Buffer.alloc(140);
    var pos = 0;
    header.writeUInt32LE(rpcData.version, pos); pos += 4;
    header.write(prevHashReversed, pos, 32, 'hex'); pos += 32;
    header.write(merkleRootReversed, pos, 32, 'hex'); pos += 32;
    header.write(saplingRoot, pos, 32, 'hex'); pos += 32;
    header.writeUInt32LE(nTimeOverride || rpcData.curtime, pos); pos += 4;
    header.write(util.reverseBuffer(Buffer.from(rpcData.bits, 'hex')).toString('hex'), pos, 4, 'hex'); pos += 4;
    // nonce placeholder (32 bytes zeros) - verusd replaces this
    // pos += 32 already zeros from alloc

    // solution from GBT (variable length, already hex)
    var solutionHex = rpcData.solution || '00';
    var solutionBuf = Buffer.from(solutionHex, 'hex');

    // solution length as compact varint
    var solLen = solutionBuf.length;
    var solLenBuf;
    if (solLen < 0xfd) {
        solLenBuf = Buffer.alloc(1);
        solLenBuf.writeUInt8(solLen, 0);
    } else {
        solLenBuf = Buffer.alloc(3);
        solLenBuf.writeUInt8(0xfd, 0);
        solLenBuf.writeUInt16LE(solLen, 1);
    }

    // tx count varint
    var txCount = (rpcData.transactions ? rpcData.transactions.length : 0) + 1;
    var txCountBuf;
    if (txCount < 0xfd) {
        txCountBuf = Buffer.alloc(1);
        txCountBuf.writeUInt8(txCount, 0);
    } else {
        txCountBuf = Buffer.alloc(3);
        txCountBuf.writeUInt8(0xfd, 0);
        txCountBuf.writeUInt16LE(txCount, 1);
    }

    var parts = [header, solLenBuf, solutionBuf, txCountBuf, Buffer.from(coinbaseTx, 'hex')];
    if (rpcData.transactions) {
        rpcData.transactions.forEach(function (tx) {
            parts.push(Buffer.from(tx.data, 'hex'));
        });
    }

    return Buffer.concat(parts).toString('hex');
}

function rpcCall(host, port, user, password, method, params, callback) {
    var body = JSON.stringify({ jsonrpc: '1.0', id: 1, method: method, params: params });
    var auth = 'Basic ' + Buffer.from(user + ':' + password).toString('base64');
    var req = http.request({
        host: host,
        port: port,
        method: 'POST',
        headers: {
            'Authorization': auth,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
        }
    }, function (res) {
        var data = '';
        res.on('data', function (chunk) { data += chunk; });
        res.on('end', function () {
            try { callback(null, JSON.parse(data)); }
            catch (e) { callback(e); }
        });
    });
    req.on('error', callback);
    req.write(body);
    req.end();
}

module.exports = function PbaasRegistrar(options, emitWarningLog) {
    var vrscDaemon = options.daemons[0];
    var chains = options.pbaasChains || [];
    var chainTargets = {}; // chain name -> bignum target, updated each GBT fetch

    // Calls addmergedblock on VRSC with assembled hex, retries once with nextblocktime as nTime if returned
    function submitMerged(chain, rpcData, nTimeOverride) {
        var hexdata;
        try { hexdata = assembleBlockHex(rpcData, nTimeOverride); }
        catch (e) {
            emitWarningLog('PBaaS block assembly failed for ' + chain.name + ': ' + e.message);
            return;
        }
        var userpass = chain.user + ':' + chain.password;
        rpcCall(vrscDaemon.host, vrscDaemon.port, vrscDaemon.user, vrscDaemon.password,
            'addmergedblock', [hexdata, chain.name, chain.host, chain.port, userpass],
            function (err, result) {
                if (err || (result && result.error)) {
                    emitWarningLog('addmergedblock failed for ' + chain.name + ': ' + (err ? err.message : JSON.stringify(result.error)));
                } else {
                    var res = result && result.result;
                    if (res && res.nextblocktime && !nTimeOverride) {
                        submitMerged(chain, rpcData, res.nextblocktime);
                    }
                }
            }
        );
    }

    // Fetch GBT from a PBaaS chain, assemble block hex, call addmergedblock on VRSC
    function registerChain(chain) {
        rpcCall(chain.host, chain.port, chain.user, chain.password, 'getblocktemplate', [{}], function (err, result) {
            if (err || !result || result.error) {
                emitWarningLog('PBaaS GBT failed for ' + chain.name + ': ' + (err ? err.message : JSON.stringify(result && result.error)));
                return;
            }
            var rpcData = result.result;
            if (rpcData.bits) {
                chainTargets[chain.name] = util.bignumFromBitsHex(rpcData.bits);
            }
            submitMerged(chain, rpcData);
        });
    }

    this.getAllChainNames = function() {
        return chains.map(function(chain) { return chain.name; });
    };

    // Returns array of chain names whose target the blockHash (display hex, big-endian) satisfies
    this.getMatchingChains = function(blockHash) {
        var hashBignum = bignum.fromBuffer(Buffer.from(blockHash, 'hex'), {endian: 'big', size: 32});
        return chains.filter(function(chain) {
            return chainTargets[chain.name] && hashBignum.le(chainTargets[chain.name]);
        }).map(function(chain) { return chain.name; });
    };

    // Verifies which chains actually accepted the block by calling getblock on each chain daemon.
    // Calls back with the subset of chainNames confirmed on-chain.
    this.verifyChainAcceptance = function(blockHash, chainNames, callback) {
        var accepted = [];
        var pending = chainNames.length;
        if (pending === 0) return callback([]);
        chainNames.forEach(function(name) {
            var chain = chains.find(function(c) { return c.name === name; });
            if (!chain) { if (--pending === 0) callback(accepted); return; }
            rpcCall(chain.host, chain.port, chain.user, chain.password, 'getblock', [blockHash], function(err, result) {
                if (!err && result && !result.error && result.result) {
                    accepted.push(name);
                }
                if (--pending === 0) callback(accepted);
            });
        });
    };

    this.registerAll = function () {
        chains.forEach(registerChain);
    };

    // Also poll on independent timers per chain block time
    var intervals = { vARRR: 10000, CHIPS: 10000, VDEX: 10000 };
    chains.forEach(function (chain) {
        var interval = intervals[chain.name] || 10000;
        setInterval(function () { registerChain(chain); }, interval);
        registerChain(chain); // register immediately on start
    });
};
