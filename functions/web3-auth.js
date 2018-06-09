const NodeCache = require('node-cache');
const ethUtil = require('ethereumjs-util');
const sigUtil = require('eth-sig-util');
const uuidv4 = require('uuid/v4');
const crypto = require('crypto');

const secret = uuidv4();
let cache = new NodeCache({
    stdTTL: 600
});

class EthereumAuth {

    constructor(options) {

        return (req, res, next) => {

            const def = {
                message: "Sign this message to authenticate: " + new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '') 
            }

            this.options = Object.assign(def, options)

            if (req.params["address"]) {
                const address = req.params["address"];
                if (ethUtil.isValidAddress(address)) {
                    req.ethauth = this.createChallenge(address);
                }
            }

            if (req.params["unsigned"] && req.params["signed"]) {
                const address = this.checkChallenge(
                    req.params["unsigned"],
                    req.params["signed"]
                )
                req.ethauth = {address: address};
            }

            next();
        }
    }

    createChallenge(address) {

        const hash = this.options.message;        
        var challenge = ethUtil.bufferToHex(new Buffer(hash, 'utf8'))
        cache.set(address, challenge);
        return challenge;

    }

    checkChallenge(challenge, sig) {

        const address = sigUtil.recoverPersonalSignature({
            data: challenge,
            sig: sig
        });
        
        const storedChallenge = cache.get(address);

        if (storedChallenge === challenge) {
            cache.del(address);
            return address;
        }

        return false;
    }
}


module.exports = EthereumAuth;


