const functions = require('firebase-functions');
const ethUtil = require('ethereumjs-util');
const sigUtil = require('eth-sig-util');
const crypto = require('crypto');
const admin = require('firebase-admin');

challengeHmacKey = functions.config().netvote.secret.challengehmackey;

const COLLECTION_CHALLENGE_CACHE = "challengeCache"


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
                    putChallenge(address, req.ethauth).then(()=>{
                        console.log("EthereumAuth: challenge creation complete")
                        next();
                    })
                } else {
                    console.error("EthereumAuth: ethUtil.isValidAddress returned false for "+address)
                }
            } 

            if (req.params["unsigned"] && req.params["signed"]) {
                this.checkChallenge(
                    req.params["unsigned"],
                    req.params["signed"]
                ).then((address) => {
                    req.ethauth = {address: address};
                    console.log("EthereumAuth: returning address: "+address)
                    next();
                })
            } 

        }
    }

    createChallenge(address) {
        const hash = this.options.message;        
        var challenge = ethUtil.bufferToHex(new Buffer(hash, 'utf8'))
        return challenge;
    }

    checkChallenge(challenge, sig) {

        const address = sigUtil.recoverPersonalSignature({
            data: challenge,
            sig: sig
        });

        let now = new Date().getTime();

        return getChallenge(address, challenge).then((doc) => {
            if (doc.exists) {
                if (doc.data().expires > now) {
                    return address;
                } else {
                    console.error("checkChallenge: challenge expired")
                }
            } else {
                console.error("checkChallenge: doc not found (invalid challenge)")
            }
            return false;
        })
    }
}

const putChallenge = (address, challenge) => {
    let db = admin.firestore()
    let now = new Date().getTime();
    return db.collection(COLLECTION_CHALLENGE_CACHE).doc(toHmac(address+challenge)).set({
        expires: (now + 60000),
        timestamp: now  // for cache expiration
    })
}

const getChallenge = (address, challenge) => {
    let db = admin.firestore()
    return db.collection(COLLECTION_CHALLENGE_CACHE).doc(address).get()
}


const toHmac = (value) => {
    const hmac = crypto.createHmac('sha256', challengeHmacKey);
    hmac.update(value);
    return hmac.digest('hex');
};


module.exports = EthereumAuth;


