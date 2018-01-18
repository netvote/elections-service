const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);
const cookieParser = require('cookie-parser');
const express = require('express');
const cors = require('cors');
const HDWalletProvider = require("truffle-hdwallet-provider");
const contract = require('truffle-contract');
const uuid = require('uuid/v4');
const crypto = require('crypto');
const nJwt = require('njwt');

const COLLECTION_HASH_SECRETS = "hashSecrets";
const COLLECTION_VOTER_IDS = "voterIds";

//CONFIG
const mnemonic = functions.config().netvote.ropsten.admin.mnemonic;
const apiUrl = functions.config().netvote.ropsten.apiurl;

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
    if(uidOwnsElection(req.user.uid, req.params.address)){
        return next();
    }
    forbidden(res);
};

const createHashKey = (electionId) => {
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        console.log("secret="+storageHashSecret+", electionId="+electionId);
        const electionHmac = toHmac(electionId, storageHashSecret);
        db.collection(COLLECTION_HASH_SECRETS).doc(electionHmac).get().then((doc)=>{
            if(!doc.exists){
                db.collection(COLLECTION_HASH_SECRETS).doc(electionHmac).set({
                    secret: uuid()
                }).then(() => {
                    console.log("stored secret");
                    resolve();
                }).catch((e) => {
                    reject(e);
                })
            }else{
                resolve();
            }
        });
    });
};

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
  return true;
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

// ADMIN APIs
const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
adminApp.use(validateFirebaseIdToken);
adminApp.use(electionOwnerCheck);
adminApp.post('/keys/:address', (req, res) => {
    generateKeys(req.user.uid, req.params.address, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
});
adminApp.post('/hashsecret/:address', (req, res) => {
    createHashKey(req.params.address).then(()=>{
        res.send({"status":"ok"});
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
    let v = req.body.vote;
    if(!v){
        sendError(res, 400, "vote is required");
    }else {
        //TODO: cast vote
        res.send({txId: uuid()});
    }
});

exports.vote = functions.https.onRequest(voterApp);
