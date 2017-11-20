const abi = require('ethereumjs-abi');
const _ = require('lodash');
const Joi = require('joi');
const Transaction = require('ethereumjs-tx');
const ethUtil = require('ethereumjs-util');

const txSchema = Joi.object().keys({
    nonce: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    gasPrice: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    gasLimit: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    to: Joi.string().regex(/^0x[0-9a-fA-F]{40}$/i),
    value: Joi.string().regex(/^0x[0-9a-fA-F]{1,64}$/i),
    data: Joi.string().regex(/^0x([0-9a-fA-F]{8})*([0-9a-fA-F]{64})*$/i),
    chainId: Joi.number().integer().min(1)
}).with('nonce', 'gasPrice', 'gasLimit', 'to', 'value', 'data', 'chainId');

exports.solSHA3 = function (types, data) {
    const hash = abi.soliditySHA3(types, data);
    return hash;
};

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


exports.generateCancelOrderData = function (order) {

    const data = abi.rawEncode(['address[3]', 'uint[7]', 'bool', 'uint8', 'uint8', 'bytes32', 'bytes32'], [order.addresses, order.orderValues, order.buyNoMoreThanAmountB, order.marginSplitPercentage, order.v, order.r, order.s]).toString('hex');
    const method = abi.methodID('cancelOrder', ['address[3]', 'uint[7]', 'bool', 'uint8', 'uint8', 'bytes32', 'bytes32']).toString('hex');

    return '0x' + method + data;
};

this.generateTx = function (rawTx, account) {

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

}