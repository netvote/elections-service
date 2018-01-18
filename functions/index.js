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

//CONFIG
const mnemonic = functions.config().netvote.ropsten.admin.mnemonic;
const apiUrl = functions.config().netvote.ropsten.apiurl;
const regKeySecret = functions.config().netvote.ropsten.voterkeysecret;
const voteTokenSecret = functions.config().netvote.ropsten.votetokensecret;

const sendError = (res, code, txt) => {
    res.status(code).send({"status":"error", "text": txt);
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
        unauthorized(res);
        return;
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
    req.user = {
        uid: "test123"
    };
    if(uidOwnsElection(req.user.uid, req.param.address)){
        return next();
    }
    forbidden(res);
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
                const hmacHex = toHmac(electionId, key);
                let ref = db.collection("voterIds").doc(hmacHex);
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

const toHmac = (electionId, key) => {
    const hmac = crypto.createHmac('sha256', regKeySecret);
    hmac.update(electionId + ":" + key);
    return hmac.digest('hex');
};

const uidOwnsElection = (uid, electionId) => {
  return true;
};

const voterIdCheck = (req, res, next) => {
    let key = req.token;
    let address = req.body.address;
    let hmac = toHmac(address, key);
    let db = admin.firestore();
    db.collection("voterIds").doc(hmac).get().then((doc)=>{
        if(doc.exists && doc.data().pool === address){
            return next();
        }
        unauthorized(res);
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
};

const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
//adminApp.use(validateFirebaseIdToken);
adminApp.use(electionOwnerCheck);
adminApp.post('/keys/:address', (req, res) => {
    req.user = {
        uid: "test123"
    };
    generateKeys(req.user.uid, req.params.address, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
});

exports.admin = functions.https.onRequest(adminApp);

const voterApp = express();
voterApp.use(cors());
voterApp.use(authHeaderDecorator);
voterApp.use(voterIdCheck);
voterApp.post('/auth', (req, res) => {
    res.send("valid");
});
exports.vote = functions.https.onRequest(voterApp);
