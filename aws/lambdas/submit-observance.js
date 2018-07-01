const nv = require("./netvote-eth.js");
const nonceCounter = require("./nonce-counter.js");

const submitObservance = async(scope, submitId, reference, timestamp, observances) => {
    const nonce = await nonceCounter.getNonce(process.env.NETWORK);
    return await observances.addEntry(scope, submitId, reference, timestamp, {nonce: nonce, from: nv.gatewayAddress()});
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
        context.callbackWaitsForEmptyEventLoop = false;

    //TODO: increment nonce
    try {
        let version = event.version ? event.version : 20;
        const Observances = await nv.Observances(version);
        const observances = await Observances.deployed();
        const scope = event.scope;
        const submitId = event.submitId ? event.submitId : event.scope;
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

        const tx = await submitObservance(scope, submitId, reference, timestamp, observances);
        console.log(`submitted observance: ref=${reference}, submitId=${submitId}, tx=${tx.tx}`)
        callback(null, tx.tx)
    } catch(e) {
        console.error("error while transacting: ", e);
        callback(e, "error")
    }
};
