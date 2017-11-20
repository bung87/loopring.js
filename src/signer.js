const abi = require('ethereumjs-abi');
const _ = require('lodash');
const Joi = require('joi');
const Transaction = require('ethereumjs-tx');
const ethUtil = require('ethereumjs-util');
const BigNumber = require('bignumber.js');
const Validataor = require('./validator.js');
const BN = require('bn.js');

const txSchema = Joi.object().keys({
    nonce: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    gasPrice: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    gasLimit: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    to: Joi.string().regex(/^0x[0-9a-fA-F]{40}$/i),
    value: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    data: Joi.string().regex(/^0x([0-9a-fA-F]{8})*([0-9a-fA-F]{64})*$/i),
    chainId: Joi.number().integer().min(1)
}).with('nonce', 'gasPrice', 'gasLimit', 'to', 'value', 'data', 'chainId');
const validator = new Validataor();
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
}).with('protocol', 'owner', 'tokenS', 'tokenB', 'buyNoMoreThanAmountB', 'marginSplitPercentage').without('r', 's', 'v');

const orderTypes = ['address', 'address', 'address', 'address', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'bool', 'uint8'];
exports.signEthTx = function (tx, privateKey) {

    const result = Joi.validate(tx, txSchema);
    if (result.error) {
        return new Error(JSON.stringify(result.error.details));
    }

    const ethTx = new Transaction(tx);
    if (_.isString(privateKey)) {
        privateKey = ethUtil.toBuffer(privateKey);
    }
    ethTx.sign(privateKey);
    return '0x' + ethTx.serialize().toString('hex');
};

exports.generateTx = function (rawTx, account) {

    if (!rawTx) {
        throw new Error(" Raw Tx is required")
    }

    const valid_result = Joi.validate(rawTx, txSchema);

    if (valid_result.error) {
        throw new Error('invalid Tx data ');
    }

    if (!account) {

        throw new Error('Account is required')
    }

    if (!account.privateKey || !account.balance) {

        throw new Error('privateKey or balance is missing');

    }

    if (!validator.isValidPrivateKey(account.privateKey)) {

        throw new Error('invalid private key')
    }

    const gasLimit = new BigNumber(Number(rawTx.gasLimit));

    if (gasLimit && gasLimit.lessThan(21000)) {
        throw  new Error('gasLimit must be greater than 21000');
    }

    if (gasLimit && gasLimit.greaterThan(5000000)) {
        throw  new Error('gasLimit is too big');
    }

    const balance = new BigNumber(Number(account.balance));
    const needBalance = new BigNumber(Number(rawTx.value)) + gasLimit * new BigNumber(Number(rawTx.gasPrice));

    if (balance && balance.lessThan(needBalance)) {

        throw new Error('Balance  is not enough')
    }

    rawTx.chainId = rawTx.chainId || 1;

    const signed = this.signEthTx(rawTx, account.privateKey);
    return {
        tx: rawTx,
        signedTx: signed
    }

};

exports.signLoopringTx = function (order, privateKey) {

    const validation = Joi.validate(order, orderSchema);

    if (!validation) {
        throw new Error('Invalid Loopring Order');
    }
    const hash = abi.soliditySHA3(orderTypes, [order.protocol, order.owner, order.tokenS, order.tokenB,
        new BN(Number(order.amountS).toString(10), 10),
        new BN(Number(order.amountB).toString(10), 10),
        new BN(Number(order.timestamp).toString(10), 10),
        new BN(Number(order.ttl).toString(10), 10),
        new BN(Number(order.salt).toString(10), 10),
        new BN(Number(order.lrcFee).toString(10), 10),
        order.buyNoMoreThanAmountB,
        order.marginSplitPercentage]);

    const finalHash = ethUtil.hashPersonalMessage(hash);

    if (_.isString(privateKey)) {
        privateKey = ethUtil.toBuffer(privateKey);
    }

    const signature = ethUtil.ecsign(finalHash, privateKey);

    order.v = Number(signature.v.toString());
    order.r = '0x' + signature.r.toString('hex');
    order.s = '0x' + signature.s.toString('hex');

    return order;
};

exports.solSHA3 = function (types, data) {
   return abi.soliditySHA3(types, data);
};