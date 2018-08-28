const networks = require("./eth-networks.js");

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;

    try {
        let nv = await networks.NetvoteProvider("netvote")
        await nv.Ping();
        callback(null, JSON.stringify({status:"ok"}))
    } catch (e) {
        callback(e, "error")
    }
};
