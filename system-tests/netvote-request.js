const https = require('https');
const firebase = require('firebase');

const config = {
  apiKey: "AIzaSyCYwUBgD-jq6bgbKqvLi8zjtMbRLmStN4I",
  authDomain: "netvote2.firebaseapp.com",
  databaseURL: "https://netvote2.firebaseio.com",
  projectId: "netvote2",
  storageBucket: "netvote2.appspot.com",
  messagingSenderId: "861498385067"
};

const app = firebase.initializeApp(config);

const netvoteRequest = (method, path, postObj, headers) => {
  return new Promise((resolve,reject) => {
    const postData = (postObj) ? JSON.stringify(postObj) : null;

    let reqHeaders = (postData) ? {
      'Content-Type': 'application/json',
      'Content-Length': postData.length
    } : {}

    if(headers){
      for(key in headers){
        if(headers.hasOwnProperty(key)){
          reqHeaders[key] = headers[key];
        }
      }
    }

    if(!reqHeaders['Authorization']){
      reqHeaders['Authorization'] = 'Bearer '+process.env.NETVOTE_TEST_API_KEY;
    }

    const options = {
      hostname: 'netvote2.firebaseapp.com',
      port: 443,
      path: `${path}`,
      method: method,
      headers: reqHeaders
    };
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (d) => {
        body += d.toString();
      });
      res.on('end', () => {
        resolve(JSON.parse(body))
      });
    });
  
    req.on('error', (e) => {
      reject(e);
    });
    if(postData) {
      req.write(postData);
    }
    req.end();
  })
}

const netvoteGet = (path, headers) => {
  return netvoteRequest('GET', path, null, headers);
};

const netvotePost = (path, postObj, headers) => {
  return netvoteRequest('POST', path, postObj, headers);
};

const netvoteTxRequest = async(method, path, postObj, headers) => {
  return new Promise(async (resolve, reject) => {
    let txRes = await netvoteRequest(method, path, postObj, headers);
    let db = app.firestore();
    db.settings({ timestampsInSnapshots: true})
    if(!txRes.collection) {
      reject(new Error("Expected txRes to have txId: "+JSON.stringify(txRes)))
    }
    let sub = db.collection(txRes.collection).doc(txRes.txId).onSnapshot((doc) => {
      if(doc.data().status === "complete") {
        sub();
        resolve(doc.data());
      } else if (doc.data().status === "error") {
        reject(new Error("error with result"))
      }
    })
  });
}

const netvoteTxGet = async (path, headers) => {
  return netvoteTxRequest('GET', path, null, headers);
};


const netvoteTxPost = async (path, postObj, headers) => {
  return netvoteTxRequest('POST', path, postObj, headers);
};

const getElection = async (electionId) => {
  let db = app.firestore();
  db.settings({ timestampsInSnapshots: true})
  let doc = await db.collection("deployedElections").doc(electionId).get()
  if(!doc.exists){
    throw new Error("doc "+electionId+" does not exist")
  }
  return doc.data();
}

module.exports = {
  GetDeployedElection: async(electionId) => {
    return getElection(electionId);
  },
	CreateElection: async(obj) => {
    return await netvoteTxPost("/admin/election", obj)
  },
  ActivateElection: async(obj) => {
    return await netvoteTxPost("/admin/election/activate", obj)
  },
  GenerateVoterKeys: async(obj) => {
    return await netvotePost("/admin/election/keys", obj)
  },
  GetVoterToken: async(obj, key) => {
    let res = await netvotePost("/vote/auth", obj, {
      Authorization: `Bearer ${key}`
    })
    return res.token;
  },
  CastVote: async(obj, token) => {
    return await netvoteTxPost("/vote/cast", obj, {
      Authorization: `Bearer ${token}`
    })
  },
  CastVoteAsync: async(obj, token) => {
    return await netvotePost("/vote/cast", obj, {
      Authorization: `Bearer ${token}`
    })
  },
  CloseElection: async(obj) => {
    return new Promise( async (resolve, reject) => {
      await netvoteTxPost("/admin/election/close", obj)
      let db = app.firestore();
      db.settings({ timestampsInSnapshots: true})
      let sub = db.collection('deployedElections').doc(obj.electionId).onSnapshot((doc) => {
        if(doc.exists){
          if(doc.data().resultsAvailable){
            sub();
            resolve(doc.data())
          }
        }
      })
    })
  },
  TallyElection: async(electionId) => {
    let res = await netvoteTxGet(`/tally/election/${electionId}`)
    return JSON.parse(res.results);
  },
  LookupVote: async(electionId, txId) => {
    let res = await netvoteGet(`/vote/lookup/${electionId}/${txId}`)
    return JSON.parse(res.results);
  }
}
