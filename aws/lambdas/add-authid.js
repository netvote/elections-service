const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient()

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
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
        if(!event.authId || !event.electionId){
            callback(null, "missing authId, electionId skipping to avoid replay")
            return;
        }

        let params = {
            TableName: "authIds",
            Item: {
                "electionId": event.electionId,
                "authId": event.authId
            }
        }
        await docClient.put(params).promise();

        callback(null, "ok");
    }catch(e){
        callback(e, "error occured")
    }
});
