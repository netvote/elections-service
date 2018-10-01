const AWS = require("aws-sdk");
const kmsClient = new AWS.KMS();
const docClient = new AWS.DynamoDB.DocumentClient();
const uuid = require('uuid/v4')
const ursa = require('ursa')

const TABLE_ELECTIONS = "elections";
const TABLE_ASYNC_JOBS = "asyncJobs";
const ENCRYPT_KEY_ARN = "arn:aws:kms:us-east-1:891335278704:key/994f296e-ce2c-4f2b-8cef-48d16644af09";


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

const setResultsAvailable = async (electionId, available) => {
    let params = {
        TableName: TABLE_ELECTIONS,
        Key:{
            "electionId": electionId
        },
        UpdateExpression: "set resultsAvailable = :ra",
        ExpressionAttributeValues:{
            ":ra": available
        }
    }
    await docClient.update(params).promise();
}

const getElection = async (electionId) => {
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

    let ttlDate = new Date();
    ttlDate.setDate(ttlDate.getDate() + 30);
    let ttlValue = Math.floor(ttlDate.getTime()/1000)
    var params = {
        TableName: TABLE_ASYNC_JOBS,
        Key:{
            "jobId": jobId
        },
        UpdateExpression: "set txResult = :o, txStatus = :s, ttlTimestamp = :t",
        ExpressionAttributeValues:{
            ":o": obj,
            ":s": status,
            ":t": ttlValue
        }
    };
    await docClient.update(params).promise();
}

const setJobSuccess = async (jobId, result) => {
    await setJobResult(jobId, result, "complete")
}

const setJobError = async (jobId, message) => {
    await setJobResult(jobId, {message: message}, "error")
}

const addKey = async (electionId, keyType, key) => {
    let obj = {
        electionId: electionId,
        keyType: keyType,
        value: key,
        encrypted: true,
        txTimestamp: new Date().getTime()
    }

    let params = {
        TableName: "electionKeys",
        Item: obj
    }
    await docClient.put(params).promise();
    return obj.electionId;
}

const addUnencryptedKey = async (electionId, keyType, key) => {
    let obj = {
        electionId: electionId,
        keyType: keyType,
        value: key,
        encrypted: false,
        txTimestamp: new Date().getTime()
    }

    let params = {
        TableName: "electionKeys",
        Item: obj
    }
    await docClient.put(params).promise();
    return obj.electionId;
}

const kmsEncrypt = async (ctx, plaintext) => {
    const params = { EncryptionContext:ctx, KeyId: ENCRYPT_KEY_ARN, Plaintext: plaintext };
    const result = await kmsClient.encrypt(params).promise()
    return result.CiphertextBlob.toString("base64");
}

const kmsDecrypt = async (ctx, encryptedString) => {
    const cipherText = Buffer.from(encryptedString, "base64");
    const params = { EncryptionContext:ctx, CiphertextBlob: cipherText };
    const result = await kmsClient.decrypt(params).promise();
    return result.Plaintext.toString();
}

const getKey = async (electionId, keyType) => {
    var params = {
        TableName: "electionKeys",
        Key:{
            "electionId": electionId,
            "keyType": keyType
        }
    };
    let data = await docClient.get(params).promise();
    return data.Item;
}

const generateElectionKey = async (electionId, keyType) => {
    const ctx = {"id": electionId,"type": keyType}
    let key = uuid();
    let encrypted = await kmsEncrypt(ctx,  key);
    await addKey(electionId, keyType, encrypted);
    return {
        plaintext: key,
        encrypted: encrypted
    }
}

const encrypt = async (id, keyType, key) => {
    const ctx = {"id": id,"type": keyType}
    return await kmsEncrypt(ctx,  key);
}

const getDecryptedKey = async (electionId, keyType) => {
    let key = await getKey(electionId, keyType);
    const ctx = {"id": electionId,"type": keyType}
    return await kmsDecrypt(ctx, key.value);
}

const generateJwtKeys = async (electionId) => {
    let keys = ursa.generatePrivateKey();
    let encryptedPrivatePem = await encrypt(electionId, keys.toPrivatePem('base64'), "jwt")
    let pubPem = keys.toPublicPem('base64');
    await addKey(electionId, "jwt-private", encryptedPrivatePem)
    await addUnencryptedKey(electionId, "jwt-public", pubPem);
}

const clearVoterKey = async (electionId) => {
    let params = {
        TableName: "electionKeys",
        Key:{
            "electionId": electionId,
            "keyType": "voter"
        },
        UpdateExpression: "set #vl = :s",
        ExpressionAttributeNames: {
            "#vl": "value"
        },
        ExpressionAttributeValues:{
            ":s": "CLEARED"
        }
    }
    await docClient.update(params).promise();
}

module.exports = { 
    generateJwtKeys: generateJwtKeys,
    setResultsAvailable: setResultsAvailable,
    generateElectionKey: generateElectionKey,
    clearVoterKey: clearVoterKey,
    getDecryptedKey: getDecryptedKey,
    addElection: addElection,
    getElection: getElection,
    setElectionStatus: setElectionStatus,
    getVotes: getVotes,
    setJobSuccess: setJobSuccess,
    setJobError: setJobError
}