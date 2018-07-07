const functions = require('firebase-functions');
const admin = require('firebase-admin');
let web3 = require('web3-utils')

admin.initializeApp({
    credential: admin.credential.cert({
        projectId: functions.config().netvote.admin.projectid,
        clientEmail: functions.config().netvote.admin.clientemail,
        privateKey: functions.config().netvote.admin.privatekey.replace(/\\n/g, '\n')
    })
});

process.env.AWS_ACCESS_KEY_ID = functions.config().netvote.secret.awsaccesskey;
process.env.AWS_SECRET_ACCESS_KEY = functions.config().netvote.secret.awssecretkey;
const AWS = require('aws-sdk');
AWS.config.update({ region: 'us-east-1' });

const cookieParser = require('cookie-parser');
const express = require('express');
const cors = require('cors');

Array.prototype.pushArray = function (arr) {
    this.push.apply(this, arr);
};

let crypto;
let nJwt;

const PHASE_BUILDING = 0;
const PHASE_VOTING = 1;
const PHASE_CLOSED = 2;

const COLLECTION_DEMO_ELECTIONS = "demoElections";
const COLLECTION_HASH_SECRETS = "hashSecrets";
const COLLECTION_VOTER_IDS = "voterIds";
const COLLECTION_VOTER_PIN_HASH_SECRET = "voterPinHashSecrets";
const COLLECTION_ENCRYPTION_KEYS = "encryptionKeys";
const COLLECTION_NETWORK = "network";
const COLLECTION_TALLY_TX = "transactionTally";
const COLLECTION_VOTE_TX = "transactionCastVote";
const COLLECTION_UPDATE_VOTE_TX = "transactionUpdateVote";
const COLLECTION_ENCRYPTION_TX = "transactionPublishKey";
const COLLECTION_CREATE_ELECTION_TX = "transactionCreateElection";
const COLLECTION_ACTIVATE_ELECTION_TX = "transactionActivateElection";
const COLLECTION_CLOSE_ELECTION_TX = "transactionCloseElection";
const COLLECTION_JWT_TRANSACTION = "transactionJwt";
const COLLECTION_DEPLOYED_ELECTIONS = "deployedElections"

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
let ipfs;
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

const initIpfs = () => {
    let IPFS = require('ipfs-mini');
    ipfs = new IPFS({ host: 'gateway.ipfs.io', port: 443, protocol: 'https' });
};

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

const atMostOnce = (collection, id) => {
    let db = admin.firestore();
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
    res.status(code).send({ "status": "error", "text": txt });
};

const unauthorized = (res) => {
    sendError(res, 401, "Unauthorized");
};

const forbidden = (res) => {
    sendError(res, 403, "Forbidden");
};

const handleTxError = (ref, e) => {
    console.error(e);
    if (e === "duplicate") {
        return true;
    }
    return ref.set({
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

const ipfsLookup = (metadataLocation) => {
    return new Promise((resolve, reject) => {
        ipfs.catJSON(metadataLocation, (err, metadata) => {
            if (err) {
                console.error(err);
                reject(err);
            }
            let decisions = [];
            metadata.ballotGroups.forEach((bg) => {
                decisions.pushArray(bg.ballotSections);
            });
            resolve({
                decisions: decisions
            });
        });
    })
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
                console.error("error encoding proto: " + errMsg);
                reject(errMsg);
                return;
            }

            let res = VoteProto.create(voteObj);
            resolve(VoteProto.encode(res).finish());
        });
    })
};

/*
const validateVote = (vote, poolAddress) => {
    return new Promise((resolve, reject) => {
        return BasePool.at(poolAddress).getBallotCount().then((bc) => {
            const ballotCount = parseInt(bc);
            if (vote.ballotVotes.length !== ballotCount) {
                reject("vote must have " + ballotCount + " ballotVotes, actual=" + vote.ballotVotes.length)
            }
            initIpfs();
            for (let i = 0; i < ballotCount; i++) {
                let ballotVote = vote.ballotVotes[i];
                // validate this ballot vote
                BasePool.at(poolAddress).getBallot(i).then((ballotAddress) => {
                    return BaseBallot.at(ballotAddress).metadataLocation()
                }).then((location) => {
                    return ipfsLookup(location)
                }).then((metadata) => {

                    if (ballotVote.choices.length !== metadata.decisions.length) {
                        reject("ballotVotes[" + i + "] should have " + metadata.decisions.length + " choices but had " + ballotVote.choices.length);
                    }

                    ballotVote.choices.forEach((c, idx) => {
                        if (!c.writeIn) {
                            if (c.selection < 0) {
                                reject("ballotVotes[" + i + "] choice[" + idx + "] cannot have a selection less than 0")
                            }
                            if (c.selection > (metadata.decisions[idx].ballotItems.length - 1)) {
                                reject("ballotVotes[" + i + "] choice[" + idx + "] must be between 0 and " + (metadata.decisions[idx].ballotItems.length - 1) + ", was=" + c.selection)
                            }
                        } else {
                            if (c.writeIn.length > 200) {
                                reject("writeIn is limited to 200 characters")
                            }
                        }
                    });
                    resolve(true);
                });
            }
        })
    });
};
*/

const electionOwnerCheck = (req, res, next) => {
    let electionId = req.body.electionId || req.body.address;
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
    let db = admin.firestore();
    const electionHmac = toHmac(electionId, storageHashSecret);
    return db.collection(collection).doc(electionHmac).delete();
};

const submitVoteTx = (address, voteId, encryptedVote, passphrase, pushToken, tokenId) => {
    return submitEthTransaction(COLLECTION_VOTE_TX, {
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote,
        passphrase: passphrase,
        pushToken: pushToken,
        tokenId: tokenId
    });
};

const submitUpdateVoteTx = (address, voteId, encryptedVote, passphrase, pushToken, tokenId) => {
    return submitEthTransaction(COLLECTION_UPDATE_VOTE_TX, {
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote,
        passphrase: passphrase,
        pushToken: pushToken,
        tokenId: tokenId
    });
};

const submitEthTransaction = (collection, obj) => {
    let db = admin.firestore();
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
        let db = admin.firestore();
        return db.collection(COLLECTION_DEPLOYED_ELECTIONS).doc(electionId).get().then((doc) => {
            if (doc.exists) {
                resolve(doc.data().demo);
            } else{
                resolve(false);
            }
        })
    })
}

const getHashKey = (electionId, collection) => {
    initUuid();
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        const electionHmac = toHmac(electionId, storageHashSecret);
        db.collection(collection).doc(electionHmac).get().then((doc) => {
            if (doc.exists) {
                resolve(doc.data().secret);
            } else {
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
    initUuid();
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

const voterIdCheck = (req, res, next) => {
    let key = req.token;
    let electionId = req.body.electionId || req.body.address;
    let hmac = calculateRegKey(electionId, key);
    let db = admin.firestore();
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
    let db = admin.firestore();
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

const voterTokenCheck = (req, res, next) => {
    initJwt();
    if (!req.token) {
        unauthorized(res);
        return;
    }
    nJwt.verify(req.token, voteTokenSecret, function (err, verifiedJwt) {
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
};

const markJwtStatus = (key, status) => {
    let db = admin.firestore();
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

const createWeightedVoterJwt = (electionId, voterId, weight) => {
    initJwt();
    let claims = {
        iss: "https://netvote.io/",
        sub: hmacVoterId(electionId + ":" + voterId),
        scope: electionId,
        weight: weight + ""
    };
    return getPins(electionId, voterId).then((pins) => {
        if (pins.pin) {
            claims.pin = pins.pin;
        }
        if (pins.decoyPin) {
            claims.decoyPin = pins.decoyPin;
        }
        let jwt = nJwt.create(claims, voteTokenSecret);
        jwt.setExpiration(new Date().getTime() + (60 * 60 * 1000));
        let db = admin.firestore();
        let key = jwt.body.jti + jwt.body.sub;
        return db.collection(COLLECTION_JWT_TRANSACTION).doc(key).set({
            status: "pending",
            timestamp: new Date().getTime()
        }).then(() => {
            return jwt.compact();
        })
    })

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
    let db = admin.firestore();
    return db.collection(COLLECTION_DEPLOYED_ELECTIONS).doc(address).get().then((doc) => {
        if (!doc.exists) {
            throw "Deployed Election does not exist: "+address
        }
        return doc.data();
    })
}

const latestContractVersion = (network) => {
    let db = admin.firestore();
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
    let db = admin.firestore();

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
adminApp.post('/election/keys', electionOwnerCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId || !req.body.count) {
        sendError(res, 400, "count & electionId are required");
        return;
    }
    if (req.body.count < 1 || req.body.count > 100) {
        sendError(res, 400, "count must be between 1 and 100");
        return;
    }
    generateKeys(req.user.uid, electionId, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/activate', electionOwnerCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    let deployedElection;
    let collection = COLLECTION_ACTIVATE_ELECTION_TX;
    return getDeployedElection(electionId).then((el) => { 
        deployedElection = el;
        return submitEthTransaction(collection, {
            status: 'pending',
            address: el.address,
            electionId: electionId
        })
    }).then((ref) => {
        let payload = {
            electionId: electionId,
            address: deployedElection.address,
            version: deployedElection.version,
            callback: collection + "/" + ref.id
        }
        let lambdaName = (deployedElection.network === "netvote") ? 'private-activate-election'  : 'netvote-activate-election';
        asyncInvokeLambda(lambdaName, payload, (error, data) => {
            if (error) {
                handleTxError(ref, error);
            } else {
                console.log("invocation completed, data:" + JSON.stringify(data))
            }
        });

        res.send({ txId: ref.id, collection: collection });
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/close', electionOwnerCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    if (!electionId) {
        sendError(res, 400, "electionId is required");
        return;
    }
    let deployedElection;
    let collection = COLLECTION_CLOSE_ELECTION_TX;
    
    return getDeployedElection(electionId).then((el) => { 
        deployedElection = el;
        return submitEthTransaction(collection, {
            status: 'pending',
            address: deployedElection.address,
            electionId: electionId
        })
    }).then((ref) => {
        let payload = {
            electionId: electionId,
            address: deployedElection.address,
            version: deployedElection.version,
            callback: collection + "/" + ref.id
        }
        let lambdaName = (deployedElection.network === "netvote") ? 'private-close-election'  : 'netvote-close-election';
        asyncInvokeLambda(lambdaName, payload, (error, data) => {
            if (error) {
                handleTxError(ref, error);
            } else {
                console.log("close invoked successfully, data:" + JSON.stringify(data))
                let revealLambdaName = (deployedElection.network === "netvote") ? 'private-reveal-key'  : 'netvote-reveal-key';
                getHashKey(electionId, COLLECTION_ENCRYPTION_KEYS).then((key) =>{
                    payload = {
                        key: key,
                        electionId: electionId,
                        address: deployedElection.address
                    }
                    asyncInvokeLambda(revealLambdaName, payload, (error, data) => {
                        if (error) {
                            handleTxError(ref, error);
                        } else {
                            console.log("reveal invoked successfully, data:" + JSON.stringify(data))
                            removeHashKey(electionId, COLLECTION_HASH_SECRETS)
                        }
                    });
                })
            }
        });
    
        res.send({ txId: ref.id, collection: collection });
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election', (req, res) => {
    let isPublic = !!(req.body.isPublic);
    let network = req.body.network || "ropsten";
    let metadataLocation = req.body.metadataLocation;
    let allowUpdates = !!(req.body.allowUpdates);
    let autoActivate = !!(req.body.autoActivate);

    if (!metadataLocation) {
        sendError(res, 400, "metadataLocation is required");
        return;
    }

    if(network !== "ropsten" && network !== "netvote") {
        sendError(res, 400, "network must be one of: ropsten, netvote (default: ropsten)")
        return;
    }

    // 3 = create election, transfer vote, post encryption key
    // 2 = create election, transfer vote
    
    let version;
    return latestContractVersion(network).then((v) => {
        version = v;
        return submitEthTransaction(COLLECTION_CREATE_ELECTION_TX, {
            type: "basic",
            network: network,
            uid: req.user.uid,
            metadataLocation: metadataLocation,
            version: v
        })
    }).then((ref) => {
        return atMostOnce(COLLECTION_CREATE_ELECTION_TX, ref.id).then(() => {
            let payload = {
                version: version,
                election: {
                    type: "basic",
                    allowUpdates: allowUpdates,
                    isPublic: isPublic,
                    metadataLocation: metadataLocation,
                    autoActivate: autoActivate,
                    uid: req.user.uid
                },
                callback: COLLECTION_CREATE_ELECTION_TX + "/" + ref.id
            }
            console.log("sending payload: "+JSON.stringify(payload))
            let lambdaName = (network === "netvote") ? 'private-create-election'  : 'netvote-create-election';
            asyncInvokeLambda(lambdaName, payload, (error, lambData) => {
                if (error) {
                    handleTxError(ref, error);
                } else {
                    console.log("invocation completed, data:" + JSON.stringify(lambData))
                    res.send({ txId: ref.id, collection: COLLECTION_CREATE_ELECTION_TX });
                }
            })
        }).catch((e) => {
            return handleTxError(ref, e);
        });
        
    }).catch((e) => {
        console.error(e);
        console.log("error while creating election: "+e)
        sendError(res, 500, e.message);
    });
});

adminApp.post('/token/election', (req, res) => {
    let isPublic = !!(req.body.isPublic);
    let metadataLocation = req.body.metadataLocation;
    let tokenAddress = req.body.tokenAddress;
    let allowUpdates = !!(req.body.allowUpdates);
    let autoActivate = !!(req.body.autoActivate);

    if (!metadataLocation) {
        sendError(res, 400, "metadataLocation is required");
        return;
    }

    if (!tokenAddress) {
        sendError(res, 400, "tokenAddress is required");
        return;
    }

    return submitEthTransaction(COLLECTION_CREATE_ELECTION_TX, {
        type: "token",
        tokenAddress: tokenAddress,
        allowUpdates: allowUpdates,
        isPublic: isPublic,
        metadataLocation: metadataLocation,
        autoActivate: autoActivate,
        uid: req.user.uid
    }).then((ref) => {
        res.send({ txId: ref.id, collection: COLLECTION_CREATE_ELECTION_TX });
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

// VOTER APIs
const voterApp = express();
voterApp.use(cors());
voterApp.use(authHeaderDecorator);

voterApp.post('/auth', voterIdCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    return createVoterJwt(electionId, req.token).then((tok) => {
        res.send({ token: tok });
    })
});

voterApp.post('/civic/auth', civicIdCheck, (req, res) => {
    let electionId = req.body.electionId || req.body.address;
    return createVoterJwt(electionId, req.token).then((tok) => {
        res.send({ token: tok });
    })
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
            address: el.address,
            txId: tx,
            version: el.version
        }

        let lambdaName = (el.network == "netvote") ? "private-get-vote" : "netvote-get-vote";
        invokeLambda(lambdaName, payload, (err, data) => {
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

let asyncInvokeLambda = (name, payload, callback) => {
    const lambda = new AWS.Lambda({ region: "us-east-1", apiVersion: '2015-03-31' });
    const lambdaParams = {
        FunctionName: name,
        InvocationType: 'Event',
        LogType: 'None',
        Payload: JSON.stringify(payload)
    };
    callback = (callback) ? callback : lambdaCallback;
    lambda.invoke(lambdaParams, callback);
}

// voterApp.post('/token/auth', tokenOwnerCheck, (req, res) => {
//     createWeightedVoterJwt(req.body.address, req.body.owner, req.weight).then((tk) => {
//         res.send({ token: tk });
//     });
// });

voterApp.post('/scan', voterTokenCheck, (req, res) => {
    markJwtStatus(req.tokenKey, "scanned").then(() => {
        res.send({ status: "ok" });
    });
});

voterApp.post('/cast', voterTokenCheck, (req, res) => {
    initCrypto();
    let encodedVote = req.body.vote;
    let voteObj;
    let voteBuff;
    let encryptedVote;
    let tokenId;
    let electionId = req.pool;
    try {
        voteBuff = Buffer.from(encodedVote, 'base64');
    } catch (e) {
        sendError(res, 400, 'must be valid base64 encoding');
        return;
    }
    let network;
    if (!voteBuff) {
        sendError(res, 400, "vote is required");
    } else {
        return decodeVote(voteBuff).then((v) => {
            voteObj = v;
            voteObj.weight = req.weight;
            voteObj.encryptionSeed = Math.floor(Math.random() * 1000000);
            return encodeVote(voteObj);
        }).then((vote) => {
            let voteId = "";
            const passphrase = req.body.passphrase ? req.body.passphrase : "none";
            getHashKey(electionId, COLLECTION_HASH_SECRETS).then((secret) => {
                const voteIdHmac = toHmac(electionId + ":" + req.voter, secret);
                voteId = web3.sha3(voteIdHmac);
                tokenId = web3.sha3(toHmac(req.tokenKey, secret));
                return encrypt(vote, electionId);
            }).then((encryptedPayload) => {
                encryptedVote = encryptedPayload;
                return getDeployedElection(electionId)
            }).then((el) => { 
                network = el.network;
                voteObj = {
                    address: el.address,
                    version: el.version,
                    network: el.network,
                    voteId: voteId,
                    encryptedVote: encryptedVote,
                    passphrase: passphrase,
                    tokenId: tokenId
                };

                return submitEthTransaction(COLLECTION_VOTE_TX, {
                    voteId: voteId,
                    status: "pending"
                });
            }).then((jobRef) => {
                markJwtStatus(req.tokenKey, "voted").then(() => {
                    let lambdaName = (network == "netvote") ? "private-cast-vote" : "netvote-cast-vote";
                    asyncInvokeLambda(lambdaName, {
                        callback: COLLECTION_VOTE_TX + "/" + jobRef.id,
                        vote: voteObj
                    }, (error, data) => {
                        if (error) {
                            handleTxError(jobRef, error);
                        } else {
                            console.log("invocation completed, data:" + JSON.stringify(data))
                        }
                    });
                    res.send({ txId: jobRef.id, collection: COLLECTION_VOTE_TX });
                })
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message)
            });
        }).catch((errorText) => {
            console.error(errorText);
            sendError(res, 400, errorText);
        });
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

tallyApp.get('/election/:electionId', (req, res) => {
    if (!req.params.electionId) {
        sendError(res, 400, "address is required");
        return;
    }
    const electionId = req.params.electionId;
    let deployedElection;
    return getDeployedElection(electionId).then((el) => {
        deployedElection = el;
        return submitEthTransaction(COLLECTION_TALLY_TX, {
            address: el.address,
            status: "pending"
        });
    }).then((jobRef) => {
        const lambdaName = (deployedElection.network == "netvote") ? "private-tally-election" : "netvote-tally-election";

        asyncInvokeLambda(lambdaName, {
            callback: COLLECTION_TALLY_TX + "/" + jobRef.id,
            address: deployedElection.address,
            version: deployedElection.version
        }, (error, data) => {
            if (error) {
                handleTxError(jobRef, error);
            } else {
                console.log("invocation completed, data:" + JSON.stringify(data))
            }
        });
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
