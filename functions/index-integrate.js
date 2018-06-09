const functions = require('firebase-functions');
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

var serviceAccount = require("./metaauth-firebase-adminsdk-kfl3h-09b084eb53.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://metaauth.firebaseio.com"
});


const app = express();
app.use(cors());

const EthereumAuth = require('./web3-auth');

const auth = new EthereumAuth();

app.post('/eth-auth/:address', auth, (req, res) => {
    if (req.ethauth) {
        res.send(req.ethauth);
    } else {
        res.status(500).send("");
    }
});

app.post('/eth-auth/:unsigned/:signed', auth, (req, res) => {
    if (req.ethauth && req.ethauth.address) {
        admin.auth().createCustomToken(req.ethauth.address)
            .then((customToken) => {
                return res.send(customToken);
            })
            .catch((error) => {
                return res.status(400).send(error);
            });        
    } else {
        res.status(400).send("");
    }
});

exports.app = functions.https.onRequest(app);

