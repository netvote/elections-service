const firebaseUpdater = require("./firebase-updater.js");

const nv = require("./netvote-eth.js");

const postEncryptionKey = async(addr, key, nonce, BaseElection) => {
    return BaseElection.at(addr).setPrivateKey(key, {nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        let version = event.version ? event.version : 15;
        const BaseElection = await nv.BaseElection(version);
        const tx = await postEncryptionKey(event.address, event.key, event.nonce, BaseElection);
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
