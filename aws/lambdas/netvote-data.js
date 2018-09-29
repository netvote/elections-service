const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient();
const uuid = require('uuid/v4')

const TABLE_ELECTIONS = "elections";
const TABLE_ASYNC_JOBS = "asyncJobs";

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

const getVotes = async (electionId) => {
    const params = {
        TableName : "votes",
        KeyConditionExpression: "electionId = :eid",
        ExpressionAttributeValues: {
            ":eid": electionId
        }
    };

    let data = await docClient.query(params).promise();
    
    result = {}

    data.Items.forEach((itm)=>{
        if(!result[itm.txStatus]){
            result[itm.txStatus] = [];
        }
        result[itm.txStatus].push(itm);
    })

    Object.keys(result).forEach((status) => {
        result[status] = result[status].sort((a,b)=>{
            return a.txTimestamp - b.txTimestamp;
        })
    });

    return result;
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

const setJobResult = async (jobId, obj, status) => {
    // firebase api calls do not have jobId, ignore
    if(!jobId) return;
    var params = {
        TableName: TABLE_ASYNC_JOBS,
        Key:{
            "jobId": jobId
        },
        UpdateExpression: "set txResult = :o, txStatus = :s",
        ExpressionAttributeValues:{
            ":o": obj,
            ":s": status,
        }
    };
    await docClient.update(params).promise();
}

const setJobSuccess = async (jobId, result) => {
    await setJobResult(jobId, result, "complete")
}

const setJobError = async (jobId, message) => {
    await setJobResult(jobId, message, "error")
}

module.exports = { 
    addElection: addElection,
    getElection: getElection,
    setElectionStatus: setElectionStatus,
    getVotes: getVotes,
    setJobSuccess: setJobSuccess,
    setJobError: setJobError
}