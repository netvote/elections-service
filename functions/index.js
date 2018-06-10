const functions = require('firebase-functions');
const admin = require('firebase-admin');

admin.initializeApp();

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
const COLLECTION_NONCE_COUNTER = "nonceCounter";
const COLLECTION_VOTE_TX = "transactionCastVote";
const COLLECTION_UPDATE_VOTE_TX = "transactionUpdateVote";
const COLLECTION_ENCRYPTION_TX = "transactionPublishKey";
const COLLECTION_CREATE_ELECTION_TX = "transactionCreateElection";
const COLLECTION_ACTIVATE_ELECTION_TX = "transactionActivateElection";
const COLLECTION_CLOSE_ELECTION_TX = "transactionCloseElection";
const COLLECTION_TOKEN_TRANSFER_TX = "transactionTokenTransfer";
const COLLECTION_JWT_TRANSACTION = "transactionJwt";

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

// GATEWAY CONFIG
const DEFAULT_GAS = 4512388;
const DEFAULT_GAS_PRICE = 1000000000000;
const DEFAULT_CHAIN_ID = 3;
const mnemonic = functions.config().netvote.eth.gateway.mnemonic;
const apiUrl = functions.config().netvote.eth.apiurl;
const gas = functions.config().netvote.eth.gas;
const gasPrice = functions.config().netvote.eth.gasprice;
const chainId = functions.config().netvote.eth.chainid;
const voteAddress = functions.config().netvote.eth.voteaddress;

const utilKey = functions.config().netvote.secret.utilkey;

let uuid;

let HDWalletProvider;
let contract;
let Web3;

// contracts
let ExternalAuthorizable;
let ElectionPhaseable;
let TokenElection;
let ERC20;
let BasicElection;
let BaseElection;
let BasePool;
let BaseBallot;
let Vote;

let web3Provider;
let web3;

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

const initEth = () => {
    if (!HDWalletProvider) {
        HDWalletProvider = require("truffle-hdwallet-provider");
        contract = require('truffle-contract');
        Web3 = require("web3");
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

const initGateway = () => {
    if (!BasicElection) {
        initEth();
        web3Provider = new HDWalletProvider(mnemonic, apiUrl);
        web3 = new Web3(web3Provider);
        web3.eth.defaultAccount = web3Provider.getAddress();
        const web3Defaults = {
            from: web3Provider.getAddress(),
            chainId: (chainId) ? parseInt(chainId) : DEFAULT_CHAIN_ID,
            gas: (gas) ? parseInt(gas) : DEFAULT_GAS,
            gasPrice: (gasPrice) ? parseInt(gasPrice) : DEFAULT_GAS_PRICE
        };

        ElectionPhaseable = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/ElectionPhaseable.json'));
        ElectionPhaseable.setProvider(web3Provider);
        ElectionPhaseable.defaults(web3Defaults);

        ExternalAuthorizable = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/ExternalAuthorizable.json'));
        ExternalAuthorizable.setProvider(web3Provider);
        ExternalAuthorizable.defaults(web3Defaults);

        BasicElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
        BasicElection.setProvider(web3Provider);
        BasicElection.defaults(web3Defaults);

        BaseElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BaseElection.json'));
        BaseElection.setProvider(web3Provider);
        BaseElection.defaults(web3Defaults);

        BasePool = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasePool.json'));
        BasePool.setProvider(web3Provider);
        BasePool.defaults(web3Defaults);

        BaseBallot = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BaseBallot.json'));
        BaseBallot.setProvider(web3Provider);
        BaseBallot.defaults(web3Defaults);

        TokenElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/TokenElection.json'));
        TokenElection.setProvider(web3Provider);
        TokenElection.defaults(web3Defaults);

        ERC20 = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/ERC20.json'));
        ERC20.setProvider(web3Provider);
        ERC20.defaults(web3Defaults);

        Vote = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/Vote.json'));
        Vote.setProvider(web3Provider);
        Vote.defaults(web3Defaults);
    }
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
        protobuf.load("./node_modules/@netvote/elections-solidity/protocol/vote.proto").then((rt) => {
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

const electionOwnerCheck = (req, res, next) => {
    uidAuthorized(req.user.uid, req.body.address).then((match) => {
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

const submitEncryptTx = (address, key, deleteHash) => {
    return submitEthTransaction(COLLECTION_ENCRYPTION_TX, {
        address: address,
        key: key,
        deleteHash: deleteHash
    });
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
    let db = admin.firestore();

    return db.collection(COLLECTION_DEMO_ELECTIONS).doc(electionId).get().then((doc) => {
        if (doc.exists) {
            return getHashKey(electionId, COLLECTION_VOTER_PIN_HASH_SECRET).then((secret) => {
                if (doc.data().pin) {
                    pins.pin = toHmac(doc.data().pin, secret);
                }
                if (doc.data().decoyPin) {
                    pins.decoyPin = toHmac(doc.data().decoyPin, secret);
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
        return db.collection(COLLECTION_DEMO_ELECTIONS).doc(electionId).get().then((doc) => {
            if (doc.exists) {
                resolve(doc.data().enabled);
            } else {
                resolve(false);
            }
        });
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

const votedAlready = (addr, voteId) => {
    return BasePool.at(addr).votes(voteId).then((res) => {
        return res !== '';
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
    initGateway();
    const uidHash = web3.sha3(uid);
    return new Promise(function (resolve, reject) {
        ExternalAuthorizable.at(electionId).isAuthorized(uidHash).then((authorized) => {
            resolve(authorized);
        });
    });
};

const uportIdCheck = (req, res, next) => {
    initUPort();
    uportCredential.receive(req.token).then((result) => {
        //console.log("uport="+JSON.stringify(result));
        req.token = result.address;
        // if(result.pushToken && result.publicEncKey){
        //     req.pushToken = result.pushToken;
        //     req.publicEncKey = result.publicEncKey;
        // }

        isDemoElection(req.body.address).then((demo) => {
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
    if (!req.body.address) {
        sendError(res, 400, "address (of election) is required");
        return;
    }
    let civicJwt = req.token;
    civicClient.exchangeCode(civicJwt)
        .then((userData) => {
            req.token = userData.userId;
            isDemoElection(req.body.address).then((demo) => {
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
    let address = req.body.address;
    let hmac = calculateRegKey(address, key);
    let db = admin.firestore();
    db.collection(COLLECTION_VOTER_IDS).doc(hmac).get().then((doc) => {
        if (doc.exists && doc.data().pool === address) {
            return next();
        }
        unauthorized(res);
    }).catch((e) => {
        sendError(res, 500, e.message);
    });
};

const tokenOwnerCheck = (req, res, next) => {
    initGateway();
    //TODO: check signature
    if (!req.body.owner) {
        sendError(res, 400, "owner (address) is required");
        return;
    }
    if (!req.body.address) {
        sendError(res, 400, "address (of election) is required");
        return;
    }

    //TODO: get balance at point in time rather than current balance
    TokenElection.at(req.body.address).tokenAddress().then((erc20address) => {
        return ERC20.at(erc20address).balanceOf(req.body.owner)
    }).then((bal) => {
        if (bal.toNumber() === 0) {
            sendError(res, 400, "This account has no balance on token");
        } else {
            req.weight = "" + web3.fromWei(bal.toNumber(), 'ether');
            return next();
        }
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

const updatesAreAllowed = (address) => {
    return BasePool.at(address).election((el) => {

    });
};

const adminNonce = () => {
    //TODO: when we separate addresses we can do so here
    return gatewayNonce();
};

const gatewayNonce = () => {
    let db = admin.firestore();
    let counterRef = db.collection(COLLECTION_NONCE_COUNTER).doc("gateway");

    return db.runTransaction((t) => {
        return t.get(counterRef).then((doc) => {
            if (!doc.exists) {
                throw "Counter does not exist!";
            }
            let newNonce = doc.data().nonce + 1;
            t.update(counterRef, { nonce: newNonce });
            return Promise.resolve(newNonce);
        });
    })
};

const web3GatewayNonce = () => {
    return new Promise(function (resolve, reject) {
        web3.eth.getTransactionCount(web3Provider.getAddress(), (err, res) => {
            resolve(res);
        });
    });
}

const sendGas = (addr, amount) => {
    return new Promise(function (resolve, reject) {
        gatewayNonce().then((nonce) => {
            try {
                web3.eth.sendTransaction({
                    to: addr,
                    value: amount,
                    from: web3Provider.getAddress()
                }, (err, res) => {
                    if (!err) {
                        resolve(res)
                    } else {
                        reject(err);
                    }
                })
            } catch (e) {
                reject(e);
            }
        })
    });
};

const inPhase = (address, phases) => {
    initGateway();
    return new Promise(function (resolve, reject) {
        ElectionPhaseable.at(address).electionPhase().then((phase) => {
            resolve(phases.indexOf(phase.toNumber()) > -1);
        });
    })
};

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

exports.util = functions.https.onRequest(utilApp);

// DEMO APIs
const demoApp = express();
demoApp.use(cors());
demoApp.use(cookieParser());

// demoApp.post('/uport/push', (req, res) => {
//     initUPort();
//     return uportCredential.attest({
//         claim: {customClaim: 12345},
//         exp: new Date().getTime() + 2592000000
//     }).then(attestationJWT => {
//             uportCredential.push(req.body.token, req.body.key, {
//                 sub: "2ovBoD33teH15Xy1GdXsKFuoGy4sEes4DDM",
//                 url: "me.uport:add?attestation=" + attestationJWT,
//                 message: "This is a test"
//             }).then(()=>{
//                 res.send({status:"ok"});
//             })
//         }
//     );
// });

demoApp.get('/qr/election/:address', (req, res) => {
    initQr();
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    sendQr(req.params.address, res);
})

demoApp.get('/key/:address', (req, res) => {
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    return isDemoElection(req.params.address).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.address, 1).then((keys) => {
                res.send({ key: keys[0] });
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        } else {
            sendError(res, 403, req.params.address + " is not a demo election");
        }
    });
});

demoApp.get('/qr/key/:address', (req, res) => {
    initQr();
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    return isDemoElection(req.params.address).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.address, 1).then((keys) => {
                sendQr(keys[0], res);
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        } else {
            sendError(res, 403, req.params.address + " is not a demo election");
        }
    });
});

exports.demo = functions.https.onRequest(demoApp);


// ADMIN APIs
const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
adminApp.use(validateFirebaseIdToken);
adminApp.post('/election/keys', electionOwnerCheck, (req, res) => {
    if (!req.body.address || !req.body.count) {
        sendError(res, 400, "count & address are required");
        return;
    }
    if (req.body.count < 1 || req.body.count > 100) {
        sendError(res, 400, "count must be between 1 and 100");
        return;
    }
    generateKeys(req.user.uid, req.body.address, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/activate', electionOwnerCheck, (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    // initializes encryption key
    return getHashKey(req.body.address, COLLECTION_ENCRYPTION_KEYS).then((key) => {
        return submitEthTransaction(COLLECTION_ACTIVATE_ELECTION_TX, {
            address: req.body.address
        })
    }).then((ref) => {
        res.send({ txId: ref.id, collection: COLLECTION_ACTIVATE_ELECTION_TX });
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/close', electionOwnerCheck, (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    return submitEthTransaction(COLLECTION_CLOSE_ELECTION_TX, {
        address: req.body.address
    }).then((ref) => {
        res.send({ txId: ref.id, collection: COLLECTION_CLOSE_ELECTION_TX });
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

let lambdaCallback = (error, data) => {
    if (error) {
        console.error("error invoking encryption lambda", error)
    } else {
        console.log("invocation completed, data:" + JSON.stringify(lambData))
    }
}

adminApp.post('/election/encryption', electionOwnerCheck, (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    let key;

    return getHashKey(req.body.address, COLLECTION_ENCRYPTION_KEYS).then((k) => {
        key = k;
        return submitEncryptTx(req.body.address, key, true);
    }).then((ref) => {
        
        let data = snap.data();
        adminNonce().then((nonce) => {
            let payload = {
                address: req.body.address,
                key: key,
                nonce: nonce,
                callback: COLLECTION_ENCRYPTION_TX + "/" + ref.id
            }
            asyncInvokeLambda('netvote-publish-encryption-key', payload);
        }).then(() => {
            return (data.deleteHash) ? removeHashKey(req.body.address, COLLECTION_HASH_SECRETS) : null
        })

        res.send({ txId: ref.id, collection: COLLECTION_ENCRYPTION_TX });
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election', (req, res) => {
    let isPublic = !!(req.body.isPublic);
    let metadataLocation = req.body.metadataLocation;
    let allowUpdates = !!(req.body.allowUpdates);
    let autoActivate = !!(req.body.autoActivate);

    if (!metadataLocation) {
        sendError(res, 400, "metadataLocation is required");
        return;
    }

    return submitEthTransaction(COLLECTION_CREATE_ELECTION_TX, {
        type: "basic",
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


exports.electionClose = functions.firestore
    .document(COLLECTION_CLOSE_ELECTION_TX + '/{id}')
    .onCreate((snap, context) => {
        initGateway();
        console.log("Close Election: " + context.params.id);
        let data = snap.data();
        return atMostOnce(COLLECTION_CLOSE_ELECTION_TX, context.params.id).then(() => {
            return adminNonce().then((nonce) => {
                return ElectionPhaseable.at(data.address).close({ nonce: nonce, from: web3Provider.getAddress() })
            });
        }).then((tx) => {
            return snap.ref.set({
                tx: tx.tx,
                status: "complete",
                completeTime: new Date().getTime()
            }, { merge: true });
        }).catch((e) => {
            return handleTxError(snap.ref, e);
        });
    });

exports.electionActivate = functions.firestore
    .document(COLLECTION_ACTIVATE_ELECTION_TX + '/{id}')
    .onCreate((snap, context) => {
        initGateway();
        console.log("Close Election: " + context.params.id);
        let data = snap.data();
        return atMostOnce(COLLECTION_ACTIVATE_ELECTION_TX, context.params.id).then(() => {
            return adminNonce().then((nonce) => {
                return ElectionPhaseable.at(data.address).activate({ nonce: nonce, from: web3Provider.getAddress() })
            });
        }).then((tx) => {
            return snap.ref.set({
                tx: tx.tx,
                status: "complete",
                completeTime: new Date().getTime()
            }, { merge: true });
        }).catch((e) => {
            return handleTxError(snap.ref, e);
        });
    });

let getNonces = (num) => {
    let noncePromises = []
    for (let i = 0; i < num; i++) {
        noncePromises.push(adminNonce())
    }
    return Promise.all(noncePromises).then((nonces)=>{
        nonces.sort((a, b) => a - b);
        return nonces;
    });
};

exports.createElection = functions.firestore
    .document(COLLECTION_CREATE_ELECTION_TX + '/{id}')
    .onCreate((snap, context) => {
        console.log("Create Election: " + context.params.id);
        let data = snap.data();

        let addr = "";
        let tx = "";
        let numberOfNonces = (data.isPublic) ? 3 : 2;

        return atMostOnce(COLLECTION_CREATE_ELECTION_TX, context.params.id).then(() => {
            return getNonces(numberOfNonces).then((n) => {
                let payload = {
                    nonces: n,
                    election: data,
                    callback: COLLECTION_CREATE_ELECTION_TX + "/" + snap.ref.id
                }
                asyncInvokeLambda('netvote-create-election', payload, (error, lambData) => {
                    if (error) {
                        handleTxError(snap.ref, error);
                    } else {
                        console.log("invocation completed, data:" + JSON.stringify(lambData))
                    }
                })
            })
        }).catch((e) => {
            return handleTxError(snap.ref, e);
        });
    });

// VOTER APIs
const voterApp = express();
voterApp.use(cors());
voterApp.use(authHeaderDecorator);

voterApp.post('/auth', voterIdCheck, (req, res) => {
    return createVoterJwt(req.body.address, req.token).then((tok) => {
        res.send({ token: tok });
    })
});

voterApp.post('/civic/auth', civicIdCheck, (req, res) => {
    return createVoterJwt(req.body.address, req.token).then((tok) => {
        res.send({ token: tok });
    })
});

// returns QR
voterApp.post('/qr/key', voterIdCheck, (req, res) => {
    return sendQrJwt(req.body.address, req.token, req.pushToken, req.publicEncKey, res);
});

// returns QR
voterApp.post('/qr/civic', civicIdCheck, (req, res) => {
    return sendQrJwt(req.body.address, req.token, req.pushToken, req.publicEncKey, res);
});

// returns QR
voterApp.post('/qr/uport', uportIdCheck, (req, res) => {
    return sendQrJwt(req.body.address, req.token, req.pushToken, req.publicEncKey, res);
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
voterApp.get('/qr/generated/:address', (req, res) => {
    initQr();
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    return isDemoElection(req.params.address).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.address, 1).then((keys) => {
                sendQrJwt(req.params.address, keys[0], undefined, undefined, res);
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        } else {
            sendError(res, 403, req.params.address + " is not a demo election");
        }
    });
});

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

voterApp.post('/token/auth', tokenOwnerCheck, (req, res) => {
    createWeightedVoterJwt(req.body.address, req.body.owner, req.weight).then((tk) => {
        res.send({ token: tk });
    });
});

voterApp.post('/scan', voterTokenCheck, (req, res) => {
    markJwtStatus(req.tokenKey, "scanned").then(() => {
        res.send({ status: "ok" });
    });
});

voterApp.post('/cast', voterTokenCheck, (req, res) => {
    initGateway();
    initCrypto();
    let encodedVote = req.body.vote;
    let voteObj;
    let voteBuff;
    let encryptedVote;
    let tokenId;
    try {
        voteBuff = Buffer.from(encodedVote, 'base64');
    } catch (e) {
        sendError(res, 400, 'must be valid base64 encoding');
        return;
    }
    let update = false;
    let collection = COLLECTION_VOTE_TX;
    if (!voteBuff) {
        sendError(res, 400, "vote is required");
    } else {
        return decodeVote(voteBuff).then((v) => {
            voteObj = v;
            voteObj.weight = req.weight;
            voteObj.encryptionSeed = Math.floor(Math.random() * 1000000);
            return true //validateVote(voteObj, req.pool)
        }).then((valid) => {
            return encodeVote(voteObj);
        }).then((vote) => {
            let voteId = "";
            const passphrase = req.body.passphrase ? req.body.passphrase : "none";
            getHashKey(req.pool, COLLECTION_HASH_SECRETS).then((secret) => {
                const voteIdHmac = toHmac(req.pool + ":" + req.voter, secret);
                voteId = web3.sha3(voteIdHmac);
                tokenId = web3.sha3(toHmac(req.tokenKey, secret));
                return encrypt(vote, req.pool);
            }).then((encryptedPayload) => {
                encryptedVote = encryptedPayload;
                return false; //votedAlready(req.pool, voteId)
            }).then((votedAlready) => {
                update = votedAlready;
                return gatewayNonce().then((nonce) => {
                    if (votedAlready) {
                        collection = COLLECTION_UPDATE_VOTE_TX
                    }
                    voteObj = {
                        address: req.pool,
                        update: update,
                        nonce: nonce,
                        voteId: voteId,
                        encryptedVote: encryptedVote,
                        passphrase: passphrase,
                        tokenId: tokenId
                    };

                    return submitEthTransaction(collection, {
                        voteId: voteId,
                        status: "pending"
                    });
                });
            }).then((jobRef) => {
                markJwtStatus(req.tokenKey, "voted").then(() => {

                    asyncInvokeLambda('netvote-cast-vote', {
                        callback: collection + "/" + jobRef.id,
                        vote: voteObj
                    }, (error, data) => {
                        if (error) {
                            handleTxError(jobRef, error);
                        } else {
                            console.log("invocation completed, data:" + JSON.stringify(data))
                        }
                    });

                    res.send({ txId: jobRef.id, collection: collection });
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



exports.vote = functions.https.onRequest(voterApp);

const api = express();
api.use('/vote', voterApp);
api.use('/admin', adminApp);
api.use('/util', utilApp);
api.use('/demo', demoApp);
exports.api = functions.https.onRequest(api);
