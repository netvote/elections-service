const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient();
const uuid = require('uuid/v4')

const TABLE_ELECTIONS = "elections";

const addElection = async (obj) => {
    if(!obj.electionId){
        obj.electionId = uuid();
    }

    obj.txTimestamp = new Date().getTime()

    let params = {
        TableName: TABLE_ELECTIONS,
        Item: obj
    }
    await docClient.put(params).promise();
    return obj.electionId;
}

const setElectionStatus = async (electionId, status) => {
    let params = {
        TableName: TABLE_ELECTIONS,
        Key:{
            "electionId": electionId
        },
        UpdateExpression: "set electionStatus = :s",
        ExpressionAttributeValues:{
            ":s": status
        }
    }
    await docClient.update(params).promise();
}

const getElection = async (electionId) => {
    console.log("get election Id: "+electionId)
    var params = {
        TableName: TABLE_ELECTIONS,
        Key:{
            "electionId": electionId
        }
    };
    let data = await docClient.get(params).promise();
    return data.Item;
}

module.exports = { 
    addElection: addElection,
    getElection: getElection,
    setElectionStatus: setElectionStatus
}