const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);
const cookieParser = require('cookie-parser');
const express = require('express');
const cors = require('cors');
const HDWalletProvider = require("truffle-hdwallet-provider");
const contract = require('truffle-contract');
const Web3 = require("web3");
const uuid = require('uuid/v4');
const crypto = require('crypto');
const nJwt = require('njwt');

const COLLECTION_HASH_SECRETS = "hashSecrets";
const COLLECTION_VOTER_IDS = "voterIds";
const COLLECTION_ENCRYPTION_KEYS = "encryptionKeys";

const ENCRYPT_ALGORITHM = "aes-256-cbc";

//CONFIG
const mnemonic = functions.config().netvote.ropsten.admin.mnemonic;
const apiUrl = functions.config().netvote.ropsten.apiurl;

const KeyRevealerElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
const revealerProvider = new HDWalletProvider(mnemonic, apiUrl);
KeyRevealerElection.setProvider(revealerProvider);
let revealerWeb3 = new Web3(revealerProvider);
revealerWeb3.eth.defaultAccount = revealerProvider.getAddress();
KeyRevealerElection.defaults({
    gas: 4612388,
    gasPrice: 1000000000000
});


const GatewayElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
const gatewayProvider = new HDWalletProvider(mnemonic, apiUrl);
GatewayElection.setProvider(gatewayProvider);
let gatewayWeb3 = new Web3(gatewayProvider);
gatewayWeb3.eth.defaultAccount = gatewayProvider.getAddress();
GatewayElection.defaults({
    gas: 4612388,
    gasPrice: 1000000000000
});

// for hmac-ing reg key for storage
const regKeySecret = functions.config().netvote.ropsten.voterkeysecret;

// for signing JWT
const voteTokenSecret = functions.config().netvote.ropsten.votetokensecret;

// for hmac-ing voterId
const voterIdHmacSecret = functions.config().netvote.ropsten.voteridhashsecret;

// for hmac-ing stored secrets
const storageHashSecret = functions.config().netvote.ropsten.storagehashsecret;

const sendError = (res, code, txt) => {
    res.status(code).send({"status":"error", "text": txt});
};

const unauthorized = (res) => {
    sendError(res, 401, "Unauthorized");
};

const forbidden = (res) => {
    sendError(res, 403, "Forbidden");
};


// adds auth header to req.token for easy retrieval
const authHeaderDecorator = (req, res, next) => {
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        req.token = req.headers.authorization.split('Bearer ')[1];
        return next();
    }
    unauthorized(res);
};

// from https://github.com/firebase/functions-samples/blob/master/authorized-https-endpoint/functions/index.js
const validateFirebaseIdToken = (req, res, next) => {
    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
        !req.cookies.__session) {
        console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
            'Make sure you authorize your request by providing the following HTTP header:',
            'Authorization: Bearer <Firebase ID Token>',
            'or by passing a "__session" cookie.');
        //TODO: remove, this is just testing
        req.user = {
            uid: "test123"
        };
        return next();
        //unauthorized(res);
    }

    let idToken;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        idToken = req.headers.authorization.split('Bearer ')[1];
    } else {
        idToken = req.cookies.__session;
    }
    admin.auth().verifyIdToken(idToken).then(decodedIdToken => {
        req.user = decodedIdToken;
        next();
    }).catch(error => {
        console.error('Error while verifying Firebase ID token:', error);
        unauthorized(res);
    });
};

const electionOwnerCheck = (req, res, next) => {
    uidOwnsElection(req.user.uid, req.body.address).then((match)=>{
        if(match){
            return next();
        }
        forbidden(res);
    }).catch((e)=>{
        console.error(e);
        forbidden(res);
    });
};

const removeHashKey = (electionId, collection) => {
    let db = admin.firestore();
    const electionHmac = toHmac(electionId, storageHashSecret);
    return db.collection(collection).doc(electionHmac).delete();
};

const getHashKey = (electionId, collection) => {
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        const electionHmac = toHmac(electionId, storageHashSecret);
        db.collection(collection).doc(electionHmac).get().then((doc)=>{
            if(doc.exists){
                resolve(doc.data().secret);
            }else{
                const secret = uuid();
                db.collection(collection).doc(electionHmac).set({
                    secret: secret
                }).then(() => {
                    resolve(secret);
                })
            }
        })
    });
}

const generateKeys = (uid, electionId, count) => {
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        let batch = db.batch();
        try {
            let keys = [];
            for (let i = 0; i < count; i++) {
                const key = uuid();
                keys.push(key);
                const hmacHex = calculateRegKey(electionId, key);
                let ref = db.collection(COLLECTION_VOTER_IDS).doc(hmacHex);
                batch.set(ref, {createdBy: uid, pool: electionId});
            }
            batch.commit().then(()=>{
                resolve(keys);
            });
        }catch(e){
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

const toHmac = (value, key) => {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(value);
    return hmac.digest('hex');
};

const uidOwnsElection = (uid, electionId) => {
    return new Promise(function (resolve, reject) {
        GatewayElection.at(electionId).createdBy().then((createdBy) => {
            resolve(createdBy === uid);
        });
    });
};

const voterIdCheck = (req, res, next) => {
    let key = req.token;
    let address = req.body.address;
    let hmac = calculateRegKey(address, key);
    let db = admin.firestore();
    db.collection(COLLECTION_VOTER_IDS).doc(hmac).get().then((doc)=>{
        if(doc.exists && doc.data().pool === address){
            return next();
        }
        unauthorized(res);
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
};

const voterTokenCheck = (req, res, next) => {
    nJwt.verify(req.token, voteTokenSecret,function(err,verifiedJwt){
        if(err){
            unauthorized(res);
        }else{
            req.voter = verifiedJwt.body.sub;
            req.election = verifiedJwt.body.scope;
            next();
        }
    });
};

const createVoterJwt = (electionId, voterId) => {
    let claims = {
        iss: "https://netvote.io/",
        sub: hmacVoterId(electionId+":"+voterId),
        scope: electionId
    };
    let jwt = nJwt.create(claims,voteTokenSecret);
    jwt.setExpiration(new Date().getTime() + (60*60*1000));
    return jwt.compact();
};

const encrypt = (text, electionId) => {
    return new Promise(function (resolve, reject) {
        getHashKey(electionId, COLLECTION_ENCRYPTION_KEYS).then((encryptionKey) => {
            let cipher = crypto.createCipher(ENCRYPT_ALGORITHM, encryptionKey);
            let encrypted = cipher.update(text, "utf8", "base64");
            encrypted += cipher.final("base64");
            resolve(encrypted);
        });
    });
};


// ADMIN APIs
const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
adminApp.use(validateFirebaseIdToken);
adminApp.use(electionOwnerCheck);
adminApp.post('/keys', (req, res) => {
    if(!req.body.address || !req.body.count){
        sendError(res, 400, "count & address are required");
        return;
    }
    generateKeys(req.user.uid, req.body.address, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
});
adminApp.post('/hashsecret', (req, res) => {
    if(!req.body.address){
        sendError(res, 400, "address is required");
        return;
    }
    getHashKey(req.body.address, COLLECTION_HASH_SECRETS).then((s)=>{
        res.send({"status":"ok"});
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
});
adminApp.post('/encryption', (req, res) => {
    if(!req.body.address){
        sendError(res, 400, "address is required");
        return;
    }
    getHashKey(req.body.address, COLLECTION_ENCRYPTION_KEYS).then((s)=>{
        return KeyRevealerElection.at(req.body.address).setPrivateKey(s)
    }).then(()=>{
        return removeHashKey(req.body.address, COLLECTION_HASH_SECRETS)
    }).then(()=>{
        res.send({"status":"success"});
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
});
exports.admin = functions.https.onRequest(adminApp);

// VOTER APIs
const voterApp = express();
voterApp.use(cors());
voterApp.use(authHeaderDecorator);

voterApp.post('/auth', voterIdCheck, (req, res) => {
    res.send({token: createVoterJwt(req.body.address, req.token)});
});

voterApp.post('/cast', voterTokenCheck, (req, res) => {
    let encodedVote = req.body.vote;
    let vote = Buffer.from(encodedVote, 'base64');
    if(!vote){
        sendError(res, 400, "vote is required");
    } else {
        let voteId = "";
        getHashKey(req.election, COLLECTION_HASH_SECRETS).then((secret)=> {
            const voteIdHmac = toHmac(req.election+":"+req.voter, secret);
            voteId = gatewayWeb3.sha3(voteIdHmac);
            return encrypt(vote, req.election);
        }).then((encryptedVote)=>{
            return GatewayElection.at(req.election).castVote(voteId, encryptedVote);
        }).then((result)=>{
            res.send({txId: result.tx});
        }).catch((e) => {
            console.error(e);
            sendError(res, 500, e.message)
        });
    }
});

exports.vote = functions.https.onRequest(voterApp);
