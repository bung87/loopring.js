const fetch = require('node-fetch');
const crypto = require('crypto');
const Validator = require('./validator.js');
const ethUtil = require('ethereumjs-util');
const Joi = require('joi');
const BigNumber = require('bignumber.js');
const _ = require('lodash');
const signer = require('./signer');
const abi = require('ethereumjs-abi');

function relay(host) {
    const request = {"jsonrpc": "2.0"};
    const validataor = new Validator();

    const orderSchema = Joi.object().keys({
        protocol: Joi.string().regex(/^0x[0-9a-fA-F]{40}$/i),
        owner: Joi.string().regex(/^0x[0-9a-fA-F]{40}$/i),
        tokenS: Joi.string().regex(/^0x[0-9a-fA-F]{40}$/i),
        tokenB: Joi.string().regex(/^0x[0-9a-fA-F]{40}$/i),
        buyNoMoreThanAmountB: Joi.boolean(),
        marginSplitPercentage: Joi.number().integer().min(0).max(100),
        r: Joi.number().integer().min(0),
        s: Joi.string().regex(/^0x[0-9a-fA-F]{64}$/i),
        v: Joi.string().regex(/^0x[0-9a-fA-F]{64}$/i),
    }).with('protocol', 'owner', 'tokenS', 'tokenB', 'buyNoMoreThanAmountB', 'marginSplitPercentage', 'r', 's', 'v');

    const orderTypes = ['address', 'address', 'address', 'address', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'bool', 'uint8'];

    this.getTransactionCount = async function (add, tag) {

        if (!validataor.isValidETHAddress(add)) {
            throw new Error('invalid ETH address');
        }

        if (!tag) {
            tag = 'latest';
        }
        if (tag !== 'latest' && tag !== 'earliest' && tag !== 'pending') {
            throw new Error('invalid  tag:' + tag);
        }

        const params = [add, tag];
        request.id = id();
        request.method = "eth_getTransactionCount";
        request.params = params;

        return await fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(res = > res.json()).then(res = > {
            if(res.error){
            throw new Error(res.error.message);
        }
        return res.result;
    })

    }

    this.getAccountBalance = async function (add, tag) {
        if (!validataor.isValidETHAddress(add)) {
            throw new Error('invalid ETH address');
        }

        if (!tag) {
            tag = 'latest';
        }
        if (tag !== 'latest' && tag !== 'earliest' && tag !== 'pending') {
            throw new Error('invalid  tag:' + tag);
        }

        const params = [add, tag];
        request.id = id();
        request.method = "eth_getBalance";
        request.params = params;

        return await fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(res = > res.json()).then(res = > {
            if(res.error){
            throw new Error(res.error.message);
        }
        return new BigNumber(Number(validHex(res.result)));
    })

    };

    this.call = async function (data, tag) {

        if (!tag) {
            tag = 'latest';
        }
        if (tag !== 'latest' && tag !== 'earliest' && tag !== 'pending') {
            throw new Error('invalid  tag:' + tag);
        }

        request.method = 'eth_call';
        request.params = [data, tag];
        request.id = id();

        return await fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(res = > res.json()).then(res = > {
            if(res.error){
            throw new Error(res.error.message);
        }
        return validHex(res.result);
    })

    };

    this.sendSignedTx = async function (tx) {

        request.id = id();
        request.method = "eth_sendRawTransaction";
        request.params = [tx];

        return await fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(res = > res.json()).then(res = > {
            if(res.error){
            throw new Error(res.error.message);
        }
        return res.result;
    });

    };

    this.getTokenBalance = async function (token, add, tag) {

        if (!validataor.isValidETHAddress(add)) {
            throw new Error('invalid ETH address' + add);
        }

        if (!validataor.isValidETHAddress(token)) {

            throw new Error('invalid token contract Address ' + token);
        }
        const method = '0x' + ethUtil.sha3('balanceOf(address)').toString('hex').slice(0, 8);
        const value = ethUtil.setLengthLeft(ethUtil.toBuffer(add), 32).toString('hex');
        const data = method + value;

        const params = {
            to: token,
            data
        };

        if (!tag) {
            tag = 'latest';
        }

        if (tag !== 'latest' && tag !== 'earliest' && tag !== 'pending') {
            throw new Error('invalid  tag:' + tag);
        }
        return new BigNumber(Number(await this.call(params, tag)));
    };

    this.getTokenAllowance = async function (token, owner, spender, tag) {

        if (!validataor.isValidETHAddress(owner)) {
            throw new Error('invalid owner address');
        }

        if (!validataor.isValidETHAddress(spender)) {
            throw new Error('invalid spender address');
        }

        if (!validataor.isValidETHAddress(token)) {

            throw new Error('invalid token Contract Address');
        }

        const method = '0x' + ethUtil.sha3('allowance(address,address)').toString('hex').slice(0, 8);

        const value = ethUtil.setLengthLeft(ethUtil.toBuffer(owner), 32).toString('hex') + ethUtil.setLengthLeft(ethUtil.toBuffer(spender), 32).toString('hex');

        const data = method + value;
        const params = {
            to: token,
            data
        };

        if (!tag) {
            tag = 'latest';
        }

        if (tag !== 'latest' && tag !== 'earliest' && tag !== 'pending') {
            throw new Error('invalid  tag:' + tag);
        }

        return new BigNumber(Number(await this.call(params, tag)));

    };

    this.setTokenAllowance = async function (token, spender, value, privateKey, gasLimit, gasPrice) {

        if (!validataor.isValidETHAddress(spender)) {
            throw new Error('invalid spender address');
        }

        if (!validataor.isValidETHAddress(token)) {

            throw new Error('invalid token Contract Address');
        }

        if (_.isNumber(value)) {

            value = '0x' + value.toString(16);
        }

        const method = '0x' + ethUtil.sha3('approve(address,uint)').toString('hex').slice(0, 8);
        const param = ethUtil.setLengthLeft(ethUtil.toBuffer(spender), 32).toString('hex') + ethUtil.setLengthLeft(ethUtil.toBuffer(value), 32).toString('hex');

        const data = method + param;

        if (_.isNumber(gasPrice)) {
            gasPrice = '0x' + gasPrice.toString(16);
        }

        if (_.isNumber(gasLimit)) {
            gasLimit = '0x' + gasLimit.toString(16);
        }


        const tx = {
            gasPrice,
            gasLimit,
            to: token,
            value: '0x0',
            data
        };

        const rawtx = await
        this.generateTx(tx, privateKey);

      return await this.sendSignedTx(rawtx.signedTx);
    };

    this.transferToken = async function (privateKey, to, token, value, gasLimit, gasPrice) {

        if (!validataor.isValidETHAddress(to)) {
            throw new Error('invalid spender address');
        }

        if (!validataor.isValidETHAddress(token)) {

            throw new Error('invalid token Contract Address');
        }

        if (_.isNumber(value)) {

            value = '0x' + value.toString(16);
        }

        const method = '0x' + ethUtil.sha3('transfer(address,uint)').toString('hex').slice(0, 8);
        const params = ethUtil.setLengthLeft(ethUtil.toBuffer(to), 32).toString('hex') + ethUtil.setLengthLeft(ethUtil.toBuffer(value), 32).toString('hex');

        const data = method + params;

        if (_.isNumber(gasPrice)) {
            gasPrice = '0x' + gasPrice.toString(16);
        }

        if (_.isNumber(gasLimit)) {
            gasLimit = '0x' + gasLimit.toString(16);
        }

        const rawtx = {
            gasLimit,
            gasPrice,
            to: token,
            value: '0x0',
            data
        };

        const tx = await this.generateTx(rawtx, privateKey);

       return await this.sendSignedTx(tx.signedTx)

    };

    this.submitLoopringOrder = async function (order) {

        request.method = 'submitOrder';
        request.params = order;
        request.id = id();

        return await
        fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()).then(res = > {
            return res;
    });

    };

    this.cancelLoopringOrder = async function (rawOrder, account, rawTx, cancelAmount) {

        const validation = Joi.validate(rawOrder, orderSchema);

        if (!validation) {
            throw new Error('Invalid Loopring Order');
        }
        const hash = abi.soliditySHA3(orderTypes, [rawOrder.protocol, rawOrder.owner, rawOrder.tokenS, rawOrder.tokenB,
            new BN(Number(rawOrder.amountS).toString(10), 10),
            new BN(Number(rawOrder.amountB).toString(10), 10),
            new BN(Number(rawOrder.timestamp).toString(10), 10),
            new BN(Number(rawOrder.ttl).toString(10), 10),
            new BN(Number(rawOrder.salt).toString(10), 10),
            new BN(Number(rawOrder.lrcFee).toString(10), 10),
            rawOrder.buyNoMoreThanAmountB,
            rawOrder.marginSplitPercentage]);

        const finalHash = ethUtil.hashPersonalMessage(hash);
        const owner = ethUtil.ecrecover(finalHash, rawOrder.v, rawOrder.r, rawOrder.s);

        const publicKey = ethUtil.privateToPublic(account.privateKey);
        const address = ethUtil.publicToAddress(publicKey);

        if (owner !== ethUtil.toChecksumAddress("0x" + address.toString('hex'))){
            throw new Error('the private Key you provided is not the owner of the order');
        }

        const order = {
            addresses: [rawOrder.owner, rawOrder.tokenS, rawOrder.tokenB],
            orderValues: [rawOrder.amountS, rawOrder.amountB, rawOrder.timestamp, rawOrder.ttl, rawOrder.salt, rawOrder.lrcFee, cancelAmount],
            buyNoMoreThanAmountB: rawOrder.buyNoMoreThanAmountB,
            marginSplitPercentage: rawOrder.marginSplitPercentage,
            v:rawOrder.v,
            r:rawOrder.r,
            s:rawOrder.s
        };

        const data = abi.rawEncode(['address[3]', 'uint[7]', 'bool', 'uint8', 'uint8', 'bytes32', 'bytes32'], [order.addresses, order.orderValues, order.buyNoMoreThanAmountB, order.marginSplitPercentage, order.v, order.r, order.s]).toString('hex');
        const method = abi.methodID('cancelOrder', ['address[3]', 'uint[7]', 'bool', 'uint8', 'uint8', 'bytes32', 'bytes32']).toString('hex');

        rawTx.data = '0x' + method + data;
        const tx = signer.generateTx(rawTX, account);
        return await this.sendSignedTx(tx.signedTx);
    }

    this.getOrders = async function (market, address, status, pageIndex, pageSize, contractVersion) {

        request.method = 'getOrders';
        request.params = {market, address, status, contractVersion, pageIndex, pageSize};
        request.id = id();

        return await
        fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()
    ).
        then(res = > {
            return res;
    })
        ;

    };

    this.getDepth = async function (market, pageIndex, pageSize, contractVersion) {
        request.method = 'getDepth';
        request.params = {market, pageIndex, pageSize, contractVersion};
        request.id = id();

        return await
        fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()
    ).
        then(res = > {
            return res;
    })
        ;
    };

    this.getTicker = async function (market) {

        request.method = 'getTicker';
        request.params = {market};
        request.id = id();

        return await
        fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()
    ).
        then(res = > {
            return res;
    })
        ;
    };

    this.getFills = async function (market, address, pageIndex, pageSize, contractVersion) {

        request.method = 'getFills';
        request.params = {market, address, pageIndex, pageSize, contractVersion};
        request.id = id();

        return await
        fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()
    ).
        then(res = > {
            return res;
    })
        ;

    };

    this.getCandleTicks = async function (market, interval, size) {

        request.method = 'getCandleTicks';
        request.params = {market, interval, size};
        request.id = id();

        return await
        fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()
    ).
        then(res = > {
            return res;
    })
        ;

    };

    this.getRingMined = async function (ringHash, orderHash, miner, pageIndex, pageSize, contractVersion) {

        request.method = 'getRingMined';
        request.params = {ringHash, orderHash, miner, pageIndex, pageSize, contractVersion};
        request.id = id();

        return await fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()).then(res = > {
            return res;
        });

    };

    this.getBalances = async function (address) {

        request.method = 'getBalances';
        request.params = {address};
        request.id = id();

        return await fetch(host, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        }).then(r = > r.json()).then(res = > {
            return res;
    })
    }

    function id() {
        return crypto.randomBytes(16).toString('hex');
    }

    function validHex(data) {

        if (data === '0x') {
            data = '0x0';
        }
        return data;
    }
}

module.exports = relay;