const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient()
const table = "nonces";
const expression = "set nonce = nonce + :val"

const getNonce = (name) => {
    return new Promise((resolve, reject) => {
        var params = {
            TableName: table,
            Key:{
                "name": name
            },
            UpdateExpression: expression,
            ExpressionAttributeValues:{
                ":val": 1
            },
            ReturnValues:"UPDATED_NEW"
        };

        docClient.update(params, function(err, data) {
            if (err) {
                console.error("Unable to update item. Error JSON:", JSON.stringify(err, null, 2));
                reject(err);
            } else {
                console.log("UpdateItem succeeded:", JSON.stringify(data, null, 2));
                resolve(data.Attributes.nonce);
            }
        });
    })
}


module.exports = {
    getNonce: async (name) => {
        return getNonce(name);
    }
}