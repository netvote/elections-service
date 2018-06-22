const firebaseUpdater = require("./firebase-updater.js");

const nv = require("./netvote-eth.js");

const activateElection = async(addr, nonce, ElectionPhaseable) => {
    return ElectionPhaseable.at(addr).activate({nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        let version = event.version ? event.version : 15;
        const ElectionPhaseable = await nv.ElectionPhaseable(version);
        const tx = await activateElection(event.address, event.nonce, ElectionPhaseable);
        console.log("activated election: "+event.address)
        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.tx,
            status: "complete"
        }, true);
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        callback(e, "ok")
    }
};
