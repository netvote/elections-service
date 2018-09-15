const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");

exports.handler = iopipe(async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;
    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        const version = event.version || 0;
        if(version < 24) {
            callback(null, "skipping due to version")
            return;
        }
        if(!event.authId || !event.electionId || !event.address || !event.network){
            callback(null, "missing authId, electionId, address or network, skipping to avoid replay")
            return;
        }
        context.iopipe.label(event.electionId);

        const nv = await networks.NetvoteProvider(event.network);
        const BasePool = await nv.BasePool(version);

        //forces to 32 bytes
        const hashedAuthId = nv.web3().utils.sha3(event.authId);

        const nonce = await nv.Nonce();
        let tx = await BasePool.at(event.address).addAuthId(hashedAuthId, {nonce: nonce, from: nv.gatewayAddress()})
        console.log({electionId: event.electionId, message:"added authId", authId: hashedAuthId, tx:tx.tx});
        callback(null, "ok")
    }catch(e){
        callback(e, "error occured")
    }
});
