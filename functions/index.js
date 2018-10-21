const functions = require('firebase-functions');
const admin = require('firebase-admin');
let web3 = require('web3-utils')
let IPFS = require('ipfs-mini');

admin.initializeApp({
    credential: admin.credential.cert({
        projectId: functions.config().netvote.admin.projectid,
        clientEmail: functions.config().netvote.admin.clientemail,
        privateKey: functions.config().netvote.admin.privatekey.replace(/\\n/g, '\n')
    })
});

admin.firestore().settings({timestampsInSnapshots: true})

process.env.AWS_ACCESS_KEY_ID = functions.config().netvote.secret.awsaccesskey;
process.env.AWS_SECRET_ACCESS_KEY = functions.config().netvote.secret.awssecretkey;

const ENCRYPT_KEY_ARN = functions.config().netvote.secret.encryptkeyarn;

const AWS = require('aws-sdk');
AWS.config.update({ region: 'us-east-1' });
const kmsClient = new AWS.KMS();
const docClient = new AWS.DynamoDB.DocumentClient();

const cookieParser = require('cookie-parser');
const express = require('express');
const cors = require('cors');

Array.prototype.pushArray = function (arr) {
    this.push.apply(this, arr);
};

let crypto;
let nJwt;

const LAMBDA_ELECTION_ADD_AUTHID = "election-add-authid"
const LAMBDA_ELECTION_PUBLISH_AUTHIDS = "election-publish-authids"
const LAMBDA_ELECTION_LOOKUP_VOTE = "election-lookup-vote"
const LAMBDA_ELECTION_CAST_VOTE = "election-cast-vote"
const LAMBDA_ELECTION_REVEAL_KEY = "election-reveal-key"
const LAMBDA_ELECTION_CLOSE = "election-close"
const LAMBDA_ELECTION_ACTIVATE = "election-activate"
const LAMBDA_ELECTION_CREATE = "election-create"
const LAMBDA_ELECTION_TALLY = "election-tally"

const COLLECTION_HASH_SECRETS = "hashSecrets";
const COLLECTION_VOTER_IDS = "voterIds";
const COLLECTION_VOTER_PIN_HASH_SECRET = "voterPinHashSecrets";
const COLLECTION_ENCRYPTION_KEYS = "encryptionKeys";
const COLLECTION_NETWORK = "network";
const COLLECTION_TALLY_TX = "transactionTally";
const COLLECTION_VOTE_TX = "transactionCastVote";
const COLLECTION_CREATE_ELECTION_TX = "transactionCreateElection";
const COLLECTION_ACTIVATE_ELECTION_TX = "transactionActivateElection";
const COLLECTION_CLOSE_ELECTION_TX = "transactionCloseElection";
const COLLECTION_JWT_TRANSACTION = "transactionJwt";
const COLLECTION_DEPLOYED_ELECTIONS = "deployedElections"
const COLLECTION_API_KEYS = "apiKeys"
const COLLECTION_ELECTION_JWT_KEYS = "electionJwtKeys";
const COLLECTION_BALLOT_GROUPS = "ballotGroups";
const COLLECTION_BALLOT_GROUP_JWT_SECRET = "ballotGroupsJwtSecret";
const COLLECTION_BALLOT_GROUP_ASSIGNMENTS = "ballotGroupAssignments";
const COLLECTION_USER_NETWORKS = "userNetworks";

const ENCRYPT_ALGORITHM = "aes-256-cbc";


// SECRETS CONFIG

// for hmac-ing reg key for storage
const regKeySecret = functions.config().netvote.secret.voterkey;

// for signing JWT
const voteTokenSecret = functions.config().netvote.secret.votetoken;

// for hmac-ing voterId
const voterIdHmacSecret = functions.config().netvote.secret.voteridhash;

// for hmac-ing stored secrets
const storageHashSecret = functions.config().netvote.secret.storagehash;


// civic
let civicCfg;
let civicSip;
let civicClient;
const utilKey = functions.config().netvote.secret.utilkey;
let uuid;
let QRCode;
let uportCfg;
let uportSigner;
let uportCredential;

const initUPort = () => {
    if (!uportCredential) {
        uportCfg = functions.config().netvote.uport;
        const uport = require("uport");
        uportSigner = uport.SimpleSigner(uportCfg.signingkey);
        uportCredential = new uport.Credentials({
            appName: uportCfg.appname,
            address: uportCfg.clientid,
            signer: uportSigner
        })
    }
};

const initCivic = () => {
    if (!civicCfg) {
        civicCfg = functions.config().netvote.civic;
        civicSip = require('civic-sip-api');
        civicClient = civicSip.newClient({
            appId: civicCfg.appid,
            prvKey: civicCfg.privatesigningkey,
            appSecret: civicCfg.secret,
        });
    }
};

const initQr = () => {
    if (!QRCode) {
        QRCode = require('qrcode');
    }
}

const getIpfsClient = (ipfsUrl) => {
    return  new IPFS({ host: ipfsUrl, port: 443, protocol: 'https' });
}

const initUuid = () => {
    if (!uuid) {
        uuid = require('uuid/v4');
    }
};

const initJwt = () => {
    if (!nJwt) {
        nJwt = require('njwt');
    }
};

const initCrypto = () => {
    if (!crypto) {
        crypto = require('crypto');
    }
};

const firestore = () => {
    let db = admin.firestore();
    return db;
}

const atMostOnce = (collection, id) => {
    let db = firestore();
    let txRef = db.collection(collection).doc(id);
    return db.runTransaction((t) => {
        return t.get(txRef).then((doc) => {
            if (!doc.exists) {
                throw "missing tx";
            }
            if (doc.data().status) {
                throw "duplicate";
            }
            t.update(txRef, { status: "pending" });
            return Promise.resolve(true);
        });
    });
};

const sendError = (res, code, txt) => {
    console.error("sending error: code="+code+", text="+txt);
    res.status(code).send({ "status": "error", "text": txt });
};

const unauthorized = (res) => {
    sendError(res, 401, "Unauthorized");
};

const forbidden = (res) => {
    sendError(res, 403, "Forbidden");
};

const handleTxError = async (ref, e) => {
    console.error(e);
    if (e === "duplicate") {
        return true;
    }
    await ref.set({
        status: "error",
        error: e.message
    }, { merge: true });
};

// adds auth header to req.token for easy retrieval
const authHeaderDecorator = (req, res, next) => {
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        req.token = req.headers.authorization.split('Bearer ')[1];
    }
    return next();
};

const getUserForApiKey = async (key) => {
    let db = firestore();
    const apiKeyHmac = toHmac(key, storageHashSecret);
    let k = await db.collection(COLLECTION_API_KEYS).doc(apiKeyHmac).get();
    if(k.exists){
        return k.data().user;
    }
    return null;
}

const getOrgId = async (uid) => {
    const db = firestore();
    const user = await db.collection("user").doc(uid).get();
    if(user.exists){
        const org = await user.data().currentOrg.get();
        if(org.exists){
            return org.id;
        }
    }
    return null;
}

// from https://github.com/firebase/functions-samples/blob/master/authorized-https-endpoint/functions/index.js
const validateFirebaseIdToken = async (req, res, next) => {
    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
        !req.cookies.__session) {
        console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
            'Make sure you authorize your request by providing the following HTTP header:',
            'Authorization: Bearer <Firebase ID Token>',
            'or by passing a "__session" cookie.');
        unauthorized(res);
        return;
    }

    let idToken;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        idToken = req.headers.authorization.split('Bearer ')[1];
    } else {
        idToken = req.cookies.__session;
    }

    //API KEY AUTH
    let keyUser = await getUserForApiKey(idToken);
    if(keyUser){
        let orgId = await getOrgId(keyUser);
        req.user = {
            uid: keyUser,
            orgId: orgId,
            api: true
        }
        return next();
    }

    //FIREBASE AUTH
    admin.auth().verifyIdToken(idToken).then( async (decodedIdToken) => {
        req.user = decodedIdToken;
        req.user.orgId = await getOrgId(req.user.uid);
        next();
    }).catch(error => {
        console.error('Error while verifying Firebase ID token:', error);
        unauthorized(res);
    });
};

const ballotGroupDemoCheck = async (req, res, next) => {
    let db = firestore();
    let bg = await db.collection(COLLECTION_BALLOT_GROUPS).doc(req.params.groupId).get();
    if(!bg.exists){
        sendError(res, 404, "group not found")
        return;
    }
    if(!bg.data().active){
        sendError(res, 409, "ballot group not active")
        return;
    }
    if(!bg.data().demo){
        unauthorized(res);
        return;
    }
    return next();
}

const ballotGroupAuthorize = async (req, res, next) => {
    let db = firestore();
    let bg = await db.collection(COLLECTION_BALLOT_GROUPS).doc(req.params.groupId).get();
    if(!bg.exists){
        sendError(res, 404, "group not found")
        return;
    }
    if(!bg.data().active){
        sendError(res, 409, "ballot group not active")
        return;
    }
    if(bg.data().orgid !== req.user.orgId){
        unauthorized(res);
        return;
    }
    return next();
};

let IPFS_URL_LIST = ["ipfs.infura.io","ipfs.netvote.io"];

const getFromIPFS = async (location) => {
    let retries = 2;
    for(let i=0; i<retries; i++){
        for(let u = 0; u<IPFS_URL_LIST.length; u++){
            try{
                let ipfs = getIpfsClient(IPFS_URL_LIST[u])
                return await getFromIPFSUnsafe(ipfs, location);
            } catch (e) {
                //already logged, try again
            }
        }
    }
    throw new Error("Error trying to access ipfs: "+location)
}

const getFromIPFSUnsafe = (ipfsObj, location) => {
    return new Promise((resolve, reject) => {
        ipfsObj.catJSON(location, (err, obj) => {
            if (err) {
                console.error(err);
                reject(err);
            }
            resolve(obj)
        });
    })
}

const ipfsLookup = async (metadataLocation) => {
    let metadata = await getFromIPFS(metadataLocation);
    let decisions = [];
    metadata.ballotGroups.forEach((bg) => {
        decisions.pushArray(bg.ballotSections);
    });
    return {
        decisions: decisions
    }
};

const voteProto = () => {
    let protobuf = require("protobufjs");
    return new Promise((resolve, reject) => {
        protobuf.load("./vote.proto").then((rt) => {
            return rt.lookupType("netvote.Vote");
        }).then((tp) => {
            resolve(tp);
        })
    });
};

const decodeVote = (voteBuff) => {
    return voteProto().then((VoteProto) => {
        return new Promise((resolve, reject) => {
            try {
                resolve(VoteProto.decode(voteBuff));
            } catch (e) {
                reject("invalid vote structure")
            }
        });
    })
};

const encodeVote = (voteObj) => {
    return voteProto().then((VoteProto) => {
        return new Promise((resolve, reject) => {
            let errMsg = VoteProto.verify(voteObj);
            if (errMsg) {
                console.error("error encoding proto: " + errMsg);Body
                reject(errMsg);
                return;
            }

            let res = VoteProto.create(voteObj);
            resolve(VoteProto.encode(res).finish());
        });
    })
};

// NOTE: these validate functions are copied from the tally API
// TODO: import tally API or extract validation into library
// spend totalPoints amongst the choices, all points must be spent
const validatePointsChoice = (choice, metadata) => {
    const c = choice;
    const selections = c.pointsAllocations;
    if (!selections || !selections.points ){
        throw new Error("INVALID selections be specified for points type");
    }
    if (selections.points.length !== (metadata.ballotItems.length)) {
        throw new Error("INVALID points must be allocated for each selection (or have 0 specified)");
    }
    let sum = 0;
    selections.points.forEach((points) => {
        sum += points;
    })
    if (sum !== metadata.totalPoints){
        throw new Error("INVALID not all points allocated, requires total of "+metadata.totalPoints);
    }
}

// strict numbering of 1-N for N choices
const validateRankedChoice = (choice, metadata) => {
    const c = choice;
    const selections = c.pointsAllocations;
    if (!selections || !selections.points ) {
        throw new Error("INVALID pointsAllocations be specified for ranked type");
    }
    if (selections.points.length !== (metadata.ballotItems.length)) {
        throw new Error("INVALID points must be allocated for each selection (or have 0 specified)");
    }
    //must contain all of 1,2,3,...N
    for(let i=1; i<=selections.points.length; i++){
        if(selections.points.indexOf(i) === -1){
            throw new Error("INVALID ranked points must include every number from 1 to number of entries")
        }
    }
}

// each entry represents an index of a choice selected, numberToSelect must be selected
const validateMultipleChoice = (choice, metadata) => {
    const c = choice;
    const selections = c.indexSelections;
    if (!selections || !selections.indexes ) {
        throw new Error("INVALID selections be specified for ranked type");
    }
    // cannot select more than allowed (default max is number of choices)
    let maxSelect = metadata.maxSelect || metadata.ballotItems.length; 
    if (selections.indexes.length > maxSelect) {
        throw new Error("INVALID must select fewer than "+maxSelect+" entries, found="+selections.indexes.length);
    }
    // cannot select fewer than allowed (default minum is 1.  0 requires explicit Abstain)
    let minSelect = metadata.minSelect || 1;
    if (selections.indexes.length < minSelect) {
        throw new Error("INVALID must select more than "+minSelect+" entries, found="+selections.indexes.length);
    }
    for(let i=1; i<=selections.indexes.length; i++){
        if (selections.indexes[i] < 0) {
            throw new Error("INVALID selection < 0: " + selections.indexes[i]);
        }
        if (selections.indexes[i] > (metadata.ballotItems.length - 1)) {
            throw new Error("INVALID selection > array: " + selections.indexes[i]);
        }
    }
}

const validateSingleChoice = (choice, metadata) => {
    const c = choice;
    if(!c.writeIn){
        if(c.selection === undefined || c.selection === null){
            throw new Error("INVALID selection must be set")
        }
        if (c.selection < 0) {
            throw new Error("INVALID selection < 0: " + c.selection);
        }
        if (c.selection > (metadata.ballotItems.length - 1)) {
            throw new Error("INVALID selection > array: " + c.selection);
        }
    }
}

const validations = {
    "points": validatePointsChoice,
    "ranked": validateRankedChoice,
    "multiple": validateMultipleChoice,
    "single": validateSingleChoice
}

const validateChoices = (choices, decisionsMetadata) => {
    if (choices.length !== decisionsMetadata.length) {
        throw new Error("INVALID all questions must be answered");
    }

    choices.forEach((c, idx) => {
        let choiceType = decisionsMetadata[idx].type || "single"
        if(!c.abstain) {
            validations[choiceType](c, decisionsMetadata[idx])
        }
    });

    return true;
};

// only supports single-tiered ballot currently
const validateVote = async (vote, metadataLocation, requireProof) => {
    const metadata = await ipfsLookup(metadataLocation)

    if(vote.ballotVotes.length !== 1){
        throw new Error("Expected 1 ballotVote, but saw "+vote.ballotVotes.length)
    }

    if(requireProof && !vote.signatureSeed){
        throw new Error("signatureSeed must be set if proofs are required")
    }

    let ballotVote = vote.ballotVotes[0];
    validateChoices(ballotVote.choices, metadata.decisions);
};

const electionOwnerCheck = (req, res, next) => {
    let electionId = req.body.electionId || req.body.address || req.params.electionId;
    if(!electionId){
        sendError(res, 400, "electionId is required")
        return;
    }
    uidAuthorized(req.user.uid, electionId).then((match) => {
        if (match) {
            return next();
        }
        forbidden(res);
    }).catch((e) => {
        console.error(e);
        forbidden(res);
    });
};

const removeHashKey = (electionId, collection) => {
    let db = firestore();
    const electionHmac = toHmac(electionId, storageHashSecret);
    return db.collection(collection).doc(electionHmac).delete();
};

const submitEthTransaction = (collection, obj) => {
    let db = firestore();
    obj.timestamp = new Date().getTime();
    return db.collection(collection).add(obj);
};

const getPins = (electionId, voterId) => {
    let pins = {}
    return getDeployedElection(electionId).then((el) => {
        if (el.demo) {
            return getHashKey(electionId, COLLECTION_VOTER_PIN_HASH_SECRET).then((secret) => {
                if (el.pin) {
                    pins.pin = toHmac(el.pin, secret);
                }
                if (el.decoyPin) {
                    pins.decoyPin = toHmac(el.decoyPin, secret);
                }
                return pins;
            })
        } else {
            return pins;
        }
    });
}

const isDemoElection = (electionId) => {
    return new Promise(function (resolve, reject) {
        let db = firestore();
        return db.collection(COLLECTION_DEPLOYED_ELECTIONS).doc(electionId).get().then((doc) => {
            if (doc.exists) {
                resolve(doc.data().demo);
            } else{
                resolve(false);
            }
        })
    })
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

let keyTypes = {
    "encryptionKeys": "encryption",
    "hashSecrets": "voter"
}

const getHashKey = async (electionId, collection) => {
    initUuid();
    let db = firestore();
    let kt = keyTypes[collection] || collection;
    const electionHmac = toHmac(electionId, storageHashSecret);
    let doc = await db.collection(collection).doc(electionHmac).get();
    const encryptionCtx = {"id": electionId,"type": kt}
    if (doc.exists) {
        if(doc.data().encrypted){
            return await kmsDecrypt(encryptionCtx, doc.data().secret)
        }
        return doc.data().secret
    } else {
        console.warn("lazy-generating "+collection+", this should never happen now, id="+electionId)
        //TODO: remove logic if above log never occurs
        const secret = uuid();
        let encrypted = await kmsEncrypt(encryptionCtx, secret);
        await db.collection(collection).doc(electionHmac).set({
            secret: encrypted,
            encrypted: true //always encrypted now
        })
        return secret;
    }
}

const generateKeys = (uid, electionId, count) => {
    initUuid();
    return new Promise(function (resolve, reject) {
        let db = firestore();
        let batch = db.batch();
        try {
            let keys = [];
            for (let i = 0; i < count; i++) {
                const key = uuid();
                keys.push(key);
                const hmacHex = calculateRegKey(electionId, key);
                let ref = db.collection(COLLECTION_VOTER_IDS).doc(hmacHex);
                batch.set(ref, { createdBy: uid, pool: electionId });
            }
            batch.commit().then(() => {
                resolve(keys);
            });
        } catch (e) {
            reject(e);
        }
    });
};

const calculateRegKey = (electionId, key) => {
    return toHmac(electionId + ":" + key, regKeySecret);
};

const hmacVoterId = (voterId) => {
    return toHmac(voterId, voterIdHmacSecret);
};

const sha256 = (value) => {
    initCrypto();
    return crypto.createHash("sha256").update(value).digest("base64");
};


const toHmac = (value, key) => {
    initCrypto();
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(value);
    return hmac.digest('hex');
};

const uidAuthorized = (uid, electionId) => {
    return new Promise(function (resolve, reject) {
        getDeployedElection(electionId).then(el=>{
            resolve(el.uid === uid);
        })
    });
};

const uportIdCheck = (req, res, next) => {
    initUPort();
    let electionId = req.body.electionId || req.body.address;
    uportCredential.receive(req.token).then((result) => {
        req.token = result.address;

        isDemoElection(electionId).then((demo) => {
            if (!demo) {
                return voterIdCheck(req, res, next);
            }
            return next();
        });
    }).catch((err) => {
        console.error(err);
        unauthorized(res);
    });
};

const civicIdCheck = (req, res, next) => {
    initCivic();
    let electionId = req.body.electionId || req.body.address;
    if (!electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    let civicJwt = req.token;
    civicClient.exchangeCode(civicJwt)
        .then((userData) => {
            req.token = userData.userId;
            isDemoElection(electionId).then((demo) => {
                if (!demo) {
                    return voterIdCheck(req, res, next);
                }
                return next();
            });
        }).catch((error) => {
            console.log(error);
            unauthorized(res);
        });
};

const getBallotGroupAssignmentKey = (groupId, shortCode) => {
    return `${groupId}_${shortCode}`.toUpperCase();
}

const ballotGroupCheck = async (req,res,next) => {
    try{
        initJwt();
        if (!req.token) {
            unauthorized(res);
            return;
        }
        if(!req.body.shortCode){
            sendError(res, 400, "shortCode is a required parameter");
            return;
        }
        
        const key = req.token.split(".")[1]
        const groupId = JSON.parse(new Buffer(key, "base64").toString("ascii")).scope;
        const shortCode = req.body.shortCode;
        const jwtSecret = await getHashKey(groupId, COLLECTION_BALLOT_GROUP_JWT_SECRET);

        nJwt.verify(req.token, jwtSecret, async (err, verifiedJwt) => {
            if (err) {
                unauthorized(res);
            } else {
                let db = firestore();
                let bgaKey = getBallotGroupAssignmentKey(groupId, shortCode);
                let assignment = await db.collection(COLLECTION_BALLOT_GROUP_ASSIGNMENTS).doc(bgaKey).get();
                if(!assignment.exists){
                    unauthorized(res);
                    return;
                }
                req.voteId = verifiedJwt.body.sub;
                req.electionId = assignment.data().electionId;
                return next();
            }
        });
    }catch(e){
        console.error("error evaluating token", e);
        unauthorized(res);
    }  
}

const voterIdCheck = (req, res, next) => {
    let key = req.token;
    let electionId = req.body.electionId || req.body.address;
    let hmac = calculateRegKey(electionId, key);
    let db = firestore();
    db.collection(COLLECTION_VOTER_IDS).doc(hmac).get().then((doc) => {
        if (doc.exists && doc.data().pool === electionId) {
            return next();
        }
        unauthorized(res);
    }).catch((e) => {
        sendError(res, 500, e.message);
    });
};

const utilKeyCheck = (req, res, next) => {
    if (!req.token || req.token !== utilKey) {
        unauthorized(res);
        return;
    }
    return nex.id
};

const checkPin = (electionId, pin, pinHmac, decoyHmac) => {
    let db = firestore();
    return getHashKey(electionId, COLLECTION_VOTER_PIN_HASH_SECRET).then((secret) => {
        const hmac = toHmac(pin, secret);
        if (hmac === pinHmac) {
            // is not decoy
            return false;
        } else if (hmac === decoyHmac) {
            // is decoy
            return true;
        } else {
            throw "invalid pin"
        }
    })
};

const getJwtSecretForElection = async (electionId) => {
    const secret = await firestore().collection(COLLECTION_ELECTION_JWT_KEYS).doc(electionId).get();
    return secret.exists ? secret.data().secret : voteTokenSecret;
}

const voterTokenCheck = async (req, res, next) => {
    try{
        initJwt();
        if (!req.token) {
            unauthorized(res);
            return;
        }
        
        //lookup secret by electionId inside token
        //default to demo key
        const key = req.token.split(".")[1]
        const electionId = JSON.parse(new Buffer(key, "base64").toString("ascii")).scope;
        const jwtSecret = await getJwtSecretForElection(electionId);

        nJwt.verify(req.token, jwtSecret, function (err, verifiedJwt) {
            if (err) {
                unauthorized(res);
            } else {
                req.voter = verifiedJwt.body.sub;
                req.pool = verifiedJwt.body.scope;
                req.weight = verifiedJwt.body.weight;
                req.tokenKey = verifiedJwt.body.jti + verifiedJwt.body.sub;
                let w = parseFloat(verifiedJwt.body.weight);
                if (isNaN(w)) {
                    req.weight = "1.0";
                }
                if (verifiedJwt.body.pin) {
                    if (!req.body.pin) {
                        unauthorized(res);
                        return;
                    }
                    checkPin(req.pool, req.body.pin, verifiedJwt.body.pin, verifiedJwt.body.decoyPin).then((decoy) => {
                        req.decoy = decoy;
                        next();
                    }).catch((e) => {
                        console.error(e);
                        unauthorized(res);
                    });
                } else {
                    return next();
                }
            }
        });
    }catch(e){
        console.error("error evaluating token", e);
        unauthorized(res);
    }  
};

const markJwtStatus = (key, status) => {
    let db = firestore();
    let jwtRef = db.collection(COLLECTION_JWT_TRANSACTION).doc(key);

    return db.runTransaction((t) => {
        return t.get(jwtRef).then((doc) => {
            if (!doc.exists) {
                throw "JWT does not exist!";
            }
            t.update(jwtRef, { status: status });
            return Promise.resolve();
        });
    });
};

const getJwtSecretForGroup = async (groupId) => {
    return await getHashKey(groupId, COLLECTION_BALLOT_GROUP_JWT_SECRET);
}

const createGroupVoterJwt = async (groupId) => {
    initUuid();
    initJwt();
    let sub = uuid();
    let claims = {
        sub: sub,
        scope: groupId,
        iss: "https://netvote.io"
    }
    const jwtSecret = await getJwtSecretForGroup(groupId);
    let jwt = nJwt.create(claims, jwtSecret);
    jwt.setExpiration(new Date().getTime() + (24 * 365 * 60 * 60 * 1000));

    let key = jwt.body.jti + jwt.body.sub;
    await initJwtForScan(key)
    //1 year
    return jwt.compact();
}

const initJwtForScan = async (key) => {
    let db = firestore();
    await db.collection(COLLECTION_JWT_TRANSACTION).doc(key).set({
        status: "pending",
        timestamp: new Date().getTime()
    })
}

const createWeightedVoterJwt = async (electionId, voterId, weight) => {
    initJwt();
    let claims = {
        iss: "https://netvote.io/",
        sub: hmacVoterId(electionId + ":" + voterId),
        scope: electionId,
        weight: weight + ""
    };

    let pins = await getPins(electionId, voterId);
    if (pins.pin) {
        claims.pin = pins.pin;
    }
    if (pins.decoyPin) {
        claims.decoyPin = pins.decoyPin;
    }
    const jwtSecret = await getJwtSecretForElection(electionId);
    let jwt = nJwt.create(claims, jwtSecret);
    jwt.setExpiration(new Date().getTime() + (60 * 60 * 1000));
    let key = jwt.body.jti + jwt.body.sub;
    await initJwtForScan(key)
    return jwt.compact();
};

const createVoterJwt = (electionId, voterId) => {
    return createWeightedVoterJwt(electionId, voterId, 1);
};

const encrypt = (text, electionId) => {
    initCrypto();
    return new Promise(function (resolve, reject) {
        getHashKey(electionId, COLLECTION_ENCRYPTION_KEYS).then((encryptionKey) => {
            let cipher = crypto.createCipher(ENCRYPT_ALGORITHM, encryptionKey);
            let encrypted = cipher.update(text, "utf8", "base64");
            encrypted += cipher.final("base64");
            resolve(encrypted);
        });
    });
};

const getDeployedElection = (address) => {
    let db = firestore();
    return db.collection(COLLECTION_DEPLOYED_ELECTIONS).doc(address).get().then((doc) => {
        if (!doc.exists) {
            throw "Deployed Election does not exist: "+address
        }
        return doc.data();
    })
}

const updateDeployedElection = async (address, obj) => {
    let db = firestore();
    return await db.collection(COLLECTION_DEPLOYED_ELECTIONS).doc(address).set(obj,{merge:true})
}

const latestContractVersion = (network) => {
    let db = firestore();
    return db.collection(COLLECTION_NETWORK).doc(network).get().then((doc) => {
        if (!doc.exists) {
            console.log("Network "+network+" does not exist.")
            throw "Network "+network+" does not exist."
        }
        console.log("returning doc for network="+network)
        return doc.data().version;  
    })
}

const sendQr = (txt, res) => {
    initQr();
    res.setHeader('Content-type', 'image/png');
    QRCode.toFileStream(res, txt, {
        color: {
            dark: "#0D364B",
            light: "#ffffff"
        }
    });
};


const sendQrJson = (obj, res) => {
    initQr();
    return new Promise(function (resolve, reject) {
        QRCode.toDataURL(JSON.stringify(obj), {
            color: {
                dark: "#0D364B",
                light: "#ffffff"
            }
        }, function (err, url) {
            res.send({
                data: obj,
                qr: url
            });
            resolve(true);
        });
    });
};


const sendQrJwt = (address, voterId, pushToken, publicEncKey, res) => {
    initQr();
    return createVoterJwt(address, voterId).then((tok) => {

        let obj = {
            "address": address,
            "token": tok,
            "callback": "https://netvote2.firebaseapp.com/vote/scan"
        };

        if (pushToken) {
            obj["pushToken"] = pushToken;
        }

        if (publicEncKey) {
            obj["publicEncKey"] = publicEncKey;
        }

        return new Promise(function (resolve, reject) {
            QRCode.toDataURL(JSON.stringify(obj), {
                color: {
                    dark: "#0D364B",
                    light: "#ffffff"
                }
            }, function (err, url) {
                res.send({
                    auth: obj,
                    qr: url
                });
                resolve(true);
            });
        });
    })
};


const purgeOldTransactions = (db, collectionPath, minTime, batchSize) => {
    let collectionRef = db.collection(collectionPath);
    let query = collectionRef.where('timestamp', '<', minTime).orderBy('timestamp').limit(batchSize);

    return new Promise((resolve, reject) => {
        deleteQueryBatch(db, query, batchSize, resolve, reject);
    });
};

const deleteQueryBatch = (db, query, batchSize, resolve, reject) => {
    query.get()
        .then((snapshot) => {
            if (snapshot.size === 0) {
                return 0;
            }

            let batch = db.batch();
            snapshot.docs.forEach((doc) => {
                batch.delete(doc.ref);
            });

            return batch.commit().then(() => {
                return snapshot.size;
            });
        }).then((numDeleted) => {

            if (numDeleted === 0) {
                resolve();
                return;
            }

            process.nextTick(() => {
                deleteQueryBatch(db, query, batchSize, resolve, reject);
            });
        })
        .catch(reject);
}


const utilApp = express();
utilApp.use(cors());
utilApp.use(authHeaderDecorator);
utilApp.use(utilKeyCheck);
utilApp.delete('/:collection/expired', (req, res) => {
    if (!req.params.collection) {
        sendError(res, 400, "address is required");
        return;
    }
    if (!req.params.collection.startsWith("transaction")) {
        sendError(res, 400, "only transaction collections are clearable");
        return;
    }

    const collection = req.params.collection;
    let db = firestore();

    //older than 1 week
    const weekInMs = 7 * 24 * 60 * 60 * 1000;
    const oneWeekAgo = new Date().getTime() - weekInMs;
    setImmediate(() => {
        purgeOldTransactions(db, collection, oneWeekAgo, 1000).then(() => {
            console.log("Cleared old transactions from " + collection);
        });
    });
    res.send({ status: "ok" });
});

// DEMO APIs
const demoApp = express();
demoApp.use(cors());
demoApp.use(cookieParser());


demoApp.get('/qr/ballotGroup/:groupId/voter', ballotGroupDemoCheck, async (req, res) => {
    initQr();
    if (!req.params.groupId) {
        sendError(res, 400, "groupId is required");
        return;
    }
    let jwt = await createGroupVoterJwt(req.params.groupId);
    
    let payload = {groupId: req.params.groupId, token: jwt, callback: "https://demo.firebaseapp.com/vote/scan"};
    return sendQrJson(payload, res);
})

demoApp.get('/qr/election/:electionId', (req, res) => {
    initQr();
    if (!req.params.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    sendQr(req.params.electionId, res);
})

demoApp.get('/key/:electionId', (req, res) => {
    if (!req.params.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    return isDemoElection(req.params.electionId).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.electionId, 1).then((keys) => {
                res.send({ key: keys[0] });
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        } else {
            sendError(res, 403, req.params.electionId + " is not a demo election");
        }
    });
});

demoApp.get('/qr/key/:electionId', (req, res) => {
    initQr();
    if (!req.params.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    return isDemoElection(req.params.electionId).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.electionId, 1).then((keys) => {
                sendQr(keys[0], res);
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        } else {
            sendError(res, 403, req.params.electionId + " is not a demo election");
        }
    });
});

// ADMIN APIs
const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
adminApp.use(validateFirebaseIdToken);

// create ballot group (for conferences, etc)
adminApp.post("/ballotGroup", async(req, res) => {
    initUuid();
    if(!req.body.name){
        sendError(res, 400, "name is required");
        return;
    }
    if(!req.body.active){
        sendError(res, 400, "active is required");
        return;
    }
    let active = !!(req.body.active);
    let db = firestore();
    let id = uuid();
    await db.collection(COLLECTION_BALLOT_GROUPS).doc(id).set({
        name: req.body.name,
        description: req.body.description || "",
        active: active,
        image: req.body.image || "",
        icon: req.body.icon || "",
        user: req.user.uid,
        orgid: req.user.orgId
    });

    res.send({id: id})
    return;
})

// create a reusable voter identity JWT for a ballotGroup
adminApp.get("/ballotGroup/:groupId/voter/jwt", ballotGroupAuthorize, async(req, res) => {
    let jwt = await createGroupVoterJwt(req.params.groupId);
    res.send({groupId: req.params.groupId, token: jwt});
})

// create a reusable voter identity JWT via QR for a ballotGroup
adminApp.get("/ballotGroup/:groupId/voter/qr", ballotGroupAuthorize, async(req, res) => {
    let jwt = await createGroupVoterJwt(req.params.groupId);
    let payload = {groupId: req.params.groupId, token: jwt};
    sendQr(JSON.stringify(payload), res);
})

adminApp.get('/apikey', async (req, res) => {
    initUuid();
    let db = firestore();
    let newKey = uuid();
    let keyHmac = toHmac(newKey, storageHashSecret)
    await db.collection(COLLECTION_API_KEYS).doc(keyHmac).set({
        user: req.user.uid
    })
    res.send({
        "key": newKey
    })
})

adminApp.post('/election/ballotGroupAssignment', electionOwnerCheck, async (req, res) => {
    if (!req.body.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    if (!req.body.groupId) {
        sendError(res, 400, "groupId is required");
        return;
    }
    if (!req.body.shortCode) {
        sendError(res, 400, "shortCode is required");
        return;
    }

    let electionId = req.body.electionId;
    let groupId = req.body.groupId;
    let shortCode = req.body.shortCode;

    let db = firestore();
    let docKey = getBallotGroupAssignmentKey(groupId, shortCode);
    let d = await db.collection(COLLECTION_BALLOT_GROUP_ASSIGNMENTS).doc(docKey).get();
    if(d.exists){
        sendError(res, 400, "short code "+shortCode+" alread exists for group");
        return;
    }

    let assignment = {};
    assignment[groupId] = shortCode;

    await db.collection(COLLECTION_BALLOT_GROUP_ASSIGNMENTS).doc(docKey).set({
        uid: req.user.uid,
        orgid: req.user.orgId,
        groupId: groupId,
        electionId: electionId,
        shortCode: shortCode
    })

    await db.collection(COLLECTION_DEPLOYED_ELECTIONS).doc(electionId).set({
        assignments: assignment
    }, {merge:true});

    res.send({"status": "ok"})
    return;
});

adminApp.post('/election/keys/upload', electionOwnerCheck, async (req, res) => {
    let electionId = req.body.electionId;
    let keyList = req.body.keys;
    let now = new Date().getTime();

    if (!electionId || !keyList) {
        sendError(res, 400, "keys & electionId are required");
        return;
    }
    
    let db = firestore();

    var i,j,keys,chunk = 500;
    for (i=0,j=keyList.length; i<j; i+=chunk) {
        keys = keyList.slice(i,i+chunk);
        let batch = db.batch();
        for (let i = 0; i < keys.length; i++) {
            const hmacHex = calculateRegKey(electionId, keys[i]);
            let ref = await db.collection(COLLECTION_VOTER_IDS).doc(hmacHex);
            batch.set(ref, { createdBy: req.user.uid, pool: electionId, createdAt: now });
        }
    
        await batch.commit();
    }
    
    res.send({"status":"ok","count": keyList.length});
    return;
});

adminApp.post('/election/keys', electionOwnerCheck, async (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId || !req.body.count) {
        sendError(res, 400, "count & electionId are required");
        return;
    }
    if (req.body.count < 1 || req.body.count > 100) {
        sendError(res, 400, "count must be between 1 and 100");
        return;
    }
    let keys = await generateKeys(req.user.uid, electionId, req.body.count);
    res.send(keys);
    return;
});

adminApp.post('/election/activate', electionOwnerCheck, async (req, res) => {
    try{
        let electionId = req.body.electionId || req.body.address; //address deprecated
        let el = await getDeployedElection(electionId);

        if(el.status !== "building"){
            let message = "Election must be in a 'building' state to be activated. state="+el.status;
            sendError(res, 409, message);
            return;
        }

        let collection = COLLECTION_ACTIVATE_ELECTION_TX;
        let ref = await submitEthTransaction(collection, {
            status: 'pending',
            address: el.address,
            electionId: electionId
        });

        let payload = {
            electionId: electionId,
            callback: collection + "/" + ref.id
        }

        try{
            await asyncInvokeLambda(LAMBDA_ELECTION_ACTIVATE, payload);
            res.send({ txId: ref.id, collection: collection });
        } catch(e){
            await handleTxError(ref, e);
            return;
        }

    } catch(e){
        console.error(e);
        sendError(res, 500, e.message);
        return;
    }
});

const voteIdAlreadyVoted = async (electionId, voteId) => {
    const params = {
        TableName : "votes",
        KeyConditionExpression: "electionId = :eid",
        ExpressionAttributeValues: {
            ":eid": electionId
        }
    };

    let data = await docClient.query(params).promise();

    for(let i=0; i<data.Items.length; i++){
        let itm = data.Items[i];
        if(itm.txStatus == "complete" && itm.voterId == voteId){
            return true;
        }
    }
    return false; 
}

const dynamoGetVoteTxs = async (electionId, status) => {
    const params = {
        TableName : "votes",
        KeyConditionExpression: "electionId = :eid",
        ExpressionAttributeValues: {
            ":eid": electionId
        }
    };

    let result = []
    let data = await docClient.query(params).promise();

    let statusCounters = {}
    data.Items.forEach((itm)=>{
        if(!statusCounters[itm.txStatus]){
            statusCounters[itm.txStatus] = 0;
        }
        statusCounters[itm.txStatus]++;
        if(!status || itm.txStatus === status){
            result.push(itm);
        }
    })

    let transactions = result.sort((a,b)=>{
        return a.txTimestamp - b.txTimestamp;
    })

    return {stats: statusCounters, transactions: transactions};
}

const getPendingVoteTransactions = async (electionId) => {
    return await dynamoGetVoteTxs(electionId, "pending");
}

const getVoteTransactions = async (electionId) => {
   return await dynamoGetVoteTxs(electionId);
}

adminApp.get('/election/:electionId/vote/transactions', electionOwnerCheck, async (req, res) => {
    let electionId = req.params.electionId;
    let voteTransactions = await getVoteTransactions(electionId);
    res.send(voteTransactions)
    return;
})

adminApp.post('/election/start', electionOwnerCheck, async (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }

    let el = await getDeployedElection(electionId);
    if(el.status !== "stopped"){
        let message = "Election must be in a 'stopped' state to be resumed. ";
        sendError(res, 409, message);
        return;
    }

    await updateDeployedElection(electionId, {status: "voting", stopped: false});
    res.send({ status: "ok" });
    return;
});

adminApp.post('/election/stop', electionOwnerCheck, async (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }

    let el = await getDeployedElection(electionId);
    if(el.status !== "voting"){
        let message = "Election must be in a 'voting' state to be stopped. ";
        if(el.status === "building"){
            message += "Activate the election first.";
        } else if(el.status === "closed"){
            message += "The election is closed.";
        }
        sendError(res, 409, message);
        return;
    }

    await updateDeployedElection(electionId, {status: "stopped", stopped: true});
    res.send({ status: "ok" });
    return;
});

adminApp.post('/election/close', electionOwnerCheck, async (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    let collection = COLLECTION_CLOSE_ELECTION_TX;
    
    let el = await getDeployedElection(electionId);

    if(el.status !== "voting" && el.status !== "stopped"){
        let message = "Election must be in a 'voting' state to be closed. ";
        if(el.status === "building"){
            message += "Activate the election first.";
        } else if(el.status === "closed"){
            message += "The election is closed already.";
        }
        sendError(res, 409, message);
        return;
    }

    if(el.closeAfter){
        let now = new Date().getTime();
        if(now < el.closeAfter){
            sendError(res, 409, `time (${now}) must be after ${el.closeAfter} to close`);
            return;
        }
    }

    if(!req.body.force){
        let pendingTx = await getPendingVoteTransactions(electionId);
        if(pendingTx.stats["pending"] > 0){
            sendError(res, 409, `There are ${pendingTx.stats["pending"]} pending vote transactions.  Include paramater force:true to override.`)
            return;
        }
    }

    let ref = await submitEthTransaction(collection, {
        status: 'pending',
        address: el.address,
        electionId: electionId
    });

    let payload = {
        electionId: electionId,
        callback: collection + "/" + ref.id
    }

    await removeHashKey(electionId, COLLECTION_HASH_SECRETS)

    //close election
    await asyncInvokeLambda(LAMBDA_ELECTION_CLOSE, payload);

    let authIdParams = {
        electionId: electionId
    }
    await asyncInvokeLambda(LAMBDA_ELECTION_PUBLISH_AUTHIDS, authIdParams);

    
    res.send({ txId: ref.id, collection: collection });
    return;
});

// uid must exist in a userNetworks collection with mainnet: true
const allowedToUseMainnet = async (uid) => {
    let db = firestore();
    let user = await db.collection(COLLECTION_USER_NETWORKS).doc(uid).get();
    return user.exists && user.data().mainnet;
}

adminApp.post('/election', async (req, res) => {
    let isPublic = !!(req.body.continuousReveal) || !!(req.body.isPublic);
    let network = req.body.network || "netvote";
    let metadataLocation = req.body.metadataReference || req.body.metadataLocation;
    let allowUpdates = !!(req.body.allowUpdates);
    let autoActivate = !!(req.body.activateNow) || !!(req.body.autoActivate);
    let requireProof = !!(req.body.requireProof);
    let closeAfter = req.body.closeAfter || 0;
    let voteStartTime = req.body.voteStartTime || 0;
    let voteEndTime = req.body.voteEndTime || 0;

    if(closeAfter && isNaN(closeAfter)){
        sendError(res, 400, "closeAfter must be numerical")
        return 
    }
    if(voteStartTime && isNaN(voteStartTime)){
        sendError(res, 400, "voteStartTime must be numerical")
        return 
    }
    if(voteEndTime && isNaN(voteEndTime)){
        sendError(res, 400, "voteEndTime must be numerical")
        return 
    }

    closeAfter = parseInt(closeAfter)
    voteEndTime = parseInt(voteEndTime)
    voteStartTime = parseInt(voteStartTime)

    let now = new Date().getTime();
    if(voteEndTime && voteEndTime < now){
        sendError(res, 400, "voteEndTime cannot be in past")
        return
    }

    if((voteStartTime && voteEndTime) && voteStartTime > voteEndTime){
        sendError(res, 400, "voteStartTime cannot be after voteEndTime")
        return
    }

    if (!metadataLocation) {
        sendError(res, 400, "metadataLocation is required");
        return;
    }

    if(network !== "ropsten" && network !== "netvote" && network !== "mainnet") {
        sendError(res, 400, "network must be one of: ropsten, netvote (default: ropsten)")
        return;
    }

    if(network === "mainnet"){
        const allowed = await allowedToUseMainnet(req.user.uid);
        if(!allowed){
            sendError(res, 403, "user is not yet allowed to use mainnet");
            return;
        }
    }

    let ref = await submitEthTransaction(COLLECTION_CREATE_ELECTION_TX, {
        type: "basic",
        network: network,
        uid: req.user.uid,
        metadataLocation: metadataLocation,
    });

    try{
        //prevents multiple firebase executions from double-sending
        await atMostOnce(COLLECTION_CREATE_ELECTION_TX, ref.id);

        //TODO: coming from API user, demo=false,  UI user is demo=true
        let isApi = !!(req.user.api);
        
        let payload = {
            network: network,
            election: {
                type: "basic",
                allowUpdates: allowUpdates,
                isPublic: isPublic,
                requireProof: requireProof,
                closeAfter: closeAfter,
                metadataLocation: metadataLocation,
                autoActivate: autoActivate,
                voteStartTime: voteStartTime,
                voteEndTime: voteEndTime,
                isDemo: !isApi, 
                uid: req.user.uid
            },
            callback: COLLECTION_CREATE_ELECTION_TX + "/" + ref.id
        }

        await asyncInvokeLambda(LAMBDA_ELECTION_CREATE, payload);

        res.send({ txId: ref.id, collection: COLLECTION_CREATE_ELECTION_TX });
    
    } catch(e) {
        await handleTxError(ref, e);
    }
    return;
});

// VOTER APIs
const voterApp = express();
voterApp.use(cors());
voterApp.use(authHeaderDecorator);

voterApp.post('/auth', voterIdCheck, async (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    let el = await getDeployedElection(electionId);

    if(el.version > 23) {
        const hashedToken = sha256(req.token);
        const params = {
            electionId: electionId,
            authId: hashedToken,
            version: el.version
        }
        await asyncInvokeLambda(LAMBDA_ELECTION_ADD_AUTHID, params);
    }

    return createVoterJwt(electionId, req.token).then((tok) => {
        res.send({ token: tok });
    })
});

voterApp.post('/ballotGroup/auth', ballotGroupCheck, async (req, res) => {
    let tok = await createVoterJwt(req.electionId, req.voteId);
    res.send({ address: req.electionId, token: tok, callback: "https://demo.netvote.io/vote/scan" });
    return;
});

voterApp.post('/civic/auth', civicIdCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    return createVoterJwt(electionId, req.token).then((tok) => {
        res.send({ token: tok });
    })
});

// returns QR
voterApp.post('/qr/shortcode', ballotGroupCheck, async (req, res) => {
    let tok = await createVoterJwt(req.electionId, req.voteId);
    return sendQrJwt(req.electionId, tok, req.pushToken, req.publicEncKey, res);
});

// returns QR
voterApp.post('/qr/key', voterIdCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    return sendQrJwt(electionId, req.token, req.pushToken, req.publicEncKey, res);
});

// returns QR
voterApp.post('/qr/civic', civicIdCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    return sendQrJwt(electionId, req.token, req.pushToken, req.publicEncKey, res);
});

// returns QR
voterApp.post('/qr/uport', uportIdCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    return sendQrJwt(electionId, req.token, req.pushToken, req.publicEncKey, res);
});

// get a particular vote tx
voterApp.get('/lookup/:electionId/:tx', (req, res) => {
    if (!req.params.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    if (!req.params.tx) {
        sendError(res, 400, "tx is required");
        return;
    }
    const electionId = req.params.electionId;
    const tx = req.params.tx;

    return getDeployedElection(electionId).then((el) => {
        const payload = {
            electionId: electionId,
            address: el.address,
            txId: tx,
            version: el.version,
            network: el.network
        }

        invokeLambda(LAMBDA_ELECTION_LOOKUP_VOTE, payload, (err, data) => {
            if(err){
                sendError(res, 500, "lambda error: "+e.message)
            } else {
                res.send({ "results": JSON.parse(data.Payload) });
            }
        })
    })
});

voterApp.get('/uport/request', (req, res) => {
    initUPort();
    uportCredential.createRequest({
        callbackUrl: req.query.callbackUrl,
        exp: new Date().getTime() + 60000
    }).then(requestToken => {
        res.send({ "requestToken": requestToken });
    });
});

// returns QR: only for demo, generates a voteId for convenience
voterApp.get('/qr/generated/:electionId', (req, res) => {
    initQr();
    if (!req.params.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    return isDemoElection(req.params.electionId).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.electionId, 1).then((keys) => {
                sendQrJwt(req.params.electionId, keys[0], undefined, undefined, res);
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        } else {
            sendError(res, 403, req.params.electionId + " is not a demo election");
        }
    });
});

let invokeLambda = (name, payload, callback) => {
    const lambda = new AWS.Lambda({ region: "us-east-1", apiVersion: '2015-03-31' });
    const lambdaParams = {
        FunctionName: name,
        InvocationType: 'RequestResponse',
        LogType: 'None',
        Payload: JSON.stringify(payload)
    };
    callback = (callback) ? callback : lambdaCallback;
    lambda.invoke(lambdaParams, callback);
}

let asyncInvokeLambda = async (name, payload) => {
    try{
        const lambda = new AWS.Lambda({ region: "us-east-1", apiVersion: '2015-03-31' });
        const lambdaParams = {
            FunctionName: name,
            InvocationType: 'Event',
            LogType: 'None',
            Payload: JSON.stringify(payload)
        };
        console.log(lambdaParams);
        return await lambda.invoke(lambdaParams).promise();
    } catch(e){
        console.error("error invoking lambda: "+name+", payload="+JSON.stringify(payload), error);
        throw e;
    }
}

// voterApp.post('/token/auth', tokenOwnerCheck, (req, res) => {
//     createWeightedVoterJwt(req.body.address, req.body.owner, req.weight).then((tk) => {
//         res.send({ token: tk });
//     });
// });

voterApp.post('/scan', async (req, res) => {
    initJwt();
    if (!req.token) {
        unauthorized(res);
        return;
    }
    const jwtObj = req.token.split(".")[1]
    const jwt = JSON.parse(new Buffer(jwtObj, "base64").toString("ascii"));
    const tokenKey = jwt.jti+jwt.sub;

    await markJwtStatus(tokenKey, "scanned");
    res.send({ status: "ok" });
    return;
});

const hashVoteId = async (electionId, voter) => {
    let secret = await getHashKey(electionId, COLLECTION_HASH_SECRETS);
    const voteIdHmac = toHmac(electionId + ":" + voter, secret);
    return web3.sha3(voteIdHmac);
}

const encryptVote = async(electionId, voteObj, weight) => {
    voteObj.weight = weight;
    voteObj.encryptionSeed = Math.floor(Math.random() * 1000000);
    let vote = await encodeVote(voteObj);
    return encrypt(vote, electionId);
}

const hashTokenId = async (electionId, tokenKey) => {
    let secret = await getHashKey(electionId, COLLECTION_HASH_SECRETS);
    return web3.sha3(toHmac(tokenKey, secret));
}

let ursa;
const initUrsa = () => {
    if(!ursa){
        ursa = require("ursa")
    }
}

const validateProof = async (voteBase64, proof) => {
    if(!proof){
        throw new Error("proof is required")
    }
    const proofObj = await getFromIPFS(proof);
    if(!proofObj.signature){
        throw new Error("signature is not specified in IPFS proof")
    }
    if(!proofObj.publicKey){
        throw new Error("publicKey is not specified in IPFS proof")
    }
    initUrsa();
    const pub = ursa.createPublicKey(proofObj.publicKey, 'base64');    
    return pub.hashAndVerify('md5', new Buffer(voteBase64), proofObj.signature, "base64");
}

// takes voterID and checks to see if it has been used so that UI can show "you have already voted"
voterApp.post('/check', voterIdCheck, async (req, res) => {
    const electionId = req.body.electionId;
    const el = await getDeployedElection(electionId);

    if(el.status !== "voting"){
        sendError(res, 409, `Election must be in 'voting' state (state=${el.status})`)
        return;
    }

    const voterId = hmacVoterId(electionId + ":" + req.token);
    const voteId = await hashVoteId(electionId, voterId);    
    const alreadyVoted = await voteIdAlreadyVoted(electionId, voteId);
    const canVote = (!alreadyVoted || (alreadyVoted && el.allowUpdates));

    res.send({ voted: alreadyVoted, canVote: canVote });
})

voterApp.post('/cast', voterTokenCheck, async (req, res) => {
    console.log("/cast vote started")
    initCrypto();
    initUuid();
    let reqId = uuid();
    let voteBuff;
    let electionId = req.pool;
    console.info(`CAST VOTE:  election=${electionId}, reqId=${reqId}`)

    let el = await getDeployedElection(electionId);

    let now = new Date().getTime();
    if(el.voteStartTime){
        if(el.voteStartTime > now) {
            sendError(res, 409, 'The time window for voting has not started')
            return;
        }
    }
    if(el.voteEndTime){
        if(el.voteEndTime < now) {
            sendError(res, 409, 'The time window for voting has ended')
            return;
        }
    }

    const proof = req.body.proof;
    try {
        voteBuff = Buffer.from(req.body.vote, 'base64');
    } catch (e) {
        sendError(res, 400, 'must be valid base64 encoding');
        return;
    }
    if (!voteBuff) {
        sendError(res, 400, "vote is required");
        return;
    } else {

        try{
            let voteId = await hashVoteId(electionId, req.voter)
            let tokenId = await hashTokenId(electionId, req.tokenKey)
            
            if(el.stopped || el.status == "stopped") {
                sendError(res, 409, "Election is no longer accepting votes");
                return;
            }
            if(el.status !== "voting"){
                let message = "Election must be in a 'voting' state. ";
                if(el.status === "building"){
                    message += "Activate the election first.";
                } else if(el.status === "closed"){
                    message += "The election is closed.";
                }
                sendError(res, 409, message);
                return;
            }
            if(el.requireProof){
                try{
                    let validProof = await validateProof(req.body.vote, proof);
                    if(!validProof){
                        sendError(res, 400, "submitted signature does not match")
                        return;
                    }
                }catch(e){
                    sendError(res, 400, e.message);
                    return;
                }
            }

            let encryptedVote;
            try{
                let voteObj = await decodeVote(voteBuff);
                await validateVote(voteObj, el.metadataLocation, el.requireProof);
                encryptedVote = await encryptVote(electionId, voteObj, req.weight)
            }catch(e){
                sendError(res, 400, e.message);
                return;
            }

            let voteObj = {
                proof: proof,
                voteId: voteId,
                encryptedVote: encryptedVote,
                tokenId: tokenId
            };

            let jobRef = await submitEthTransaction(COLLECTION_VOTE_TX, {
                electionId: electionId,
                voteId: voteId,
                status: "pending",
                reqId: reqId
            });

            await markJwtStatus(req.tokenKey, "voted")
            try{
                await asyncInvokeLambda(LAMBDA_ELECTION_CAST_VOTE, {
                    callback: COLLECTION_VOTE_TX + "/" + jobRef.id,
                    vote: voteObj,
                    electionId: electionId
                });
            }catch(e){
               await handleTxError(jobRef, e); 
               sendError(res, 500, e.message);
               return;
            }
            res.send({ txId: jobRef.id, collection: COLLECTION_VOTE_TX });
        }catch(e){
            console.error("error occured", e);
            sendError(res, 500, "error occured");
            return;
        }
        return;
    }
});

const ethApp = express();
const EthereumAuth = require('./web3-auth');
const ethAuth = new EthereumAuth();
ethApp.use(cors());

ethApp.post('/auth/:address', ethAuth, (req, res) => {
    if (req.ethauth) {
        res.send(req.ethauth);
    } else {
        sendError(res, 500, "error registering address")
    }
});

ethApp.post('/auth/:unsigned/:signed', ethAuth, (req, res) => {
    if (req.ethauth && req.ethauth.address) {
        admin.auth().createCustomToken(req.ethauth.address)
            .then((customToken) => {
                return res.send(customToken);
            })
            .catch((error) => {
                return res.status(400).send(error);
            });
    } else {
        unauthorized(res)
    }
});

const tallyApp = express();
tallyApp.use(cors());
tallyApp.use(authHeaderDecorator);

tallyApp.get('/election/:electionId', async (req, res) => {
    if (!req.params.electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    const electionId = req.params.electionId;
    let deployedElection;
    return getDeployedElection(electionId).then((el) => {
        deployedElection = el;
        if(!el.resultsAvailable){
            sendError(res, 409, "Election is not revealed. Please try again later.");
            return;
        }
        return submitEthTransaction(COLLECTION_TALLY_TX, {
            address: el.address,
            electionId: electionId,
            status: "pending"
        });
    }).then(async (jobRef) => {
        try{
            await asyncInvokeLambda(LAMBDA_ELECTION_TALLY, {
                callback: COLLECTION_TALLY_TX + "/" + jobRef.id,
                electionId: electionId,
                validateSignatures: deployedElection.requireProof
            })
        }catch(e){
            await handleTxError(jobRef, e)
        }
        res.send({ txId: jobRef.id, collection: COLLECTION_TALLY_TX });
    })   
});

const api = express();
api.use('/tally', tallyApp);
api.use('/vote', voterApp);
api.use('/admin', adminApp);
api.use('/util', utilApp);
api.use('/demo', demoApp);
api.use('/eth', ethApp);
exports.api = functions.https.onRequest(api);
