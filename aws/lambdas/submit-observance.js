const nv = require("./netvote-eth.js");
const nonceCounter = require("./nonce-counter.js");

const web3 = nv.web3();

const submitObservance = async(scope, reference, timestamp, observances) => {
    const nonce = await nonceCounter.getNonce(process.env.NETWORK);
    return await observances.addEntry(scope, reference, timestamp, {nonce: nonce, from: nv.gatewayAddress()});
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;

    //TODO: increment nonce
    try {
        let version = event.version ? event.version : 19;
        const Observances = await nv.Observances(version);
        const observances = await Observances.deployed();
        const scope = event.scope;
        const reference = event.reference;
        const timestamp = event.timestamp;
        
        if(!scope) {
            throw new Error("scope is required")
        }
        if(!reference) {
            throw new Error("reference is required")
        }
        if(!timestamp) {
            throw new Error("timestamp is required")
        }

        const refHash = web3.sha3(reference);
        const tx = await submitObservance(scope, refHash, timestamp, observances);
        console.log("submitted observance: ref="+refHash+", tx="+tx.tx)
        callback(null, tx.tx)
    } catch(e) {
        console.error("error while transacting: ", e);
        callback(e, "error")
    }
};
