const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient()

Object.defineProperty(Array.prototype, 'chunk', {
    value: function(chunkSize){
        var temporal = [];
        
        for (var i = 0; i < this.length; i+= chunkSize){
            temporal.push(this.slice(i,i+chunkSize));
        }
                
        return temporal;
    }
});

// lifted from https://stackoverflow.com/a/12646864
let shuffle = (array) => {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]]; 
    }
}

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
        if(version < 26) {
            callback(null, "skipping due to version")
            return;
        }
        if(!event.electionId || !event.address || !event.network){
            callback(null, "missing authId, electionId, address or network, skipping to avoid replay")
            return;
        }
        const nv = await networks.NetvoteProvider(event.network);
        const BasePool = await nv.BasePool(version);

        context.iopipe.label(event.electionId);

        var params = {
            TableName : "authIds",
            KeyConditionExpression: "electionId = :eid",
            ExpressionAttributeValues: {
                ":eid": event.electionId
            }
        };

        let data = await docClient.query(params).promise();

        // retrieve and sha3 each to bytes32
        let authIds = [];
        data.Items.forEach(function(item) {
            let authId = nv.web3().utils.sha3(item.authId+i)
            authIds.push(authId);
        });

        // shuffle ordering for anonymnity
        shuffle(authIds);

        // batch send in chunks of 100
        let chunks = authIds.chunk(20);
        let tasks = [];
        chunks.forEach(async (authIds) => {
            let p = new Promise(async (resolve, reject) => {
                const nonce = await nv.Nonce();
                await BasePool.at(event.address).addAuthIds(authIds, {nonce: nonce, from: nv.gatewayAddress()});
                resolve(true);
            })
            tasks.push(p);
        })

        await Promise.all(tasks);
        console.log({electionId: event.electionId, address: event.address, count: authIds.length });
        callback(null, "ok")
    }catch(e){
        callback(e, "error occured")
    }
});
