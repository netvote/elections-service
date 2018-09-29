const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const AWS = require("aws-sdk");
const ipfs = require("./netvote-ipfs.js")
const firebaseUpdater = require("./firebase-updater.js");
const database = require("./netvote-data.js")

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
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;
    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let election = await database.getElection(event.electionId);
        
        const nv = await networks.NetvoteProvider(election.network);
        const BasePool = await nv.BasePool(election.version);

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
            authIds.push(item.authId);
        });

        // shuffle ordering for anonymnity
        shuffle(authIds);

        let payload = {
            "ids": authIds,
            "count": authIds.length,
            "encoding": "sha256"
        }

        let hash = await ipfs.putItem(JSON.stringify(payload));
        const nonce = await nv.Nonce();
        await BasePool.at(election.address).setAuthIdRef(hash, {nonce: nonce, from: nv.gatewayAddress()});

        await firebaseUpdater.updateDeployedElection(event.electionId, {
            authIdReference: hash,
        });

        await database.setJobSuccess(event.jobId, statusObj)
         
        console.log({electionId: event.electionId, address: election.address, count: authIds.length, hash: hash });
        callback(null, "ok")
    }catch(e){
        await database.setJobError(event.jobId, e.message);

        callback(e, "error occured")
    }
});
