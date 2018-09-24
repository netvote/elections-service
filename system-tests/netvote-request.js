const https = require('https');
const firebase = require('firebase');
var RateLimiter = require('limiter').RateLimiter;
var limiter = new RateLimiter(25, 'second');

const config = {
  apiKey: "AIzaSyCYwUBgD-jq6bgbKqvLi8zjtMbRLmStN4I",
  authDomain: "netvote2.firebaseapp.com",
  databaseURL: "https://netvote2.firebaseio.com",
  projectId: "netvote2",
  storageBucket: "netvote2.appspot.com",
  messagingSenderId: "861498385067"
};

const app = firebase.initializeApp(config);
let firebaseDb;

const firestore = () => {
  if(!firebaseDb){
    firebaseDb = app.firestore();
    firebaseDb.settings({ timestampsInSnapshots: true})
  }
  return firebaseDb;
}

const netvoteRequest = async (method, path, postObj, headers) => {
  let maxretries = 2;
  for(let count =0; count<maxretries; count++){
    try{
      let res = await netvoteUnsafeRequest(method, path, postObj, headers);
      if(res !== undefined){
        return res;
      }
    } catch(e){
      //squash, already logged
    }
    console.log("RETRY (sleep 1s): "+path)
    await snooze(1000)
  }
  throw new Error("failed to complete request: "+method)
} 

const netvoteUnsafeRequest = (method, path, postObj, headers) => {
  return new Promise((resolve,reject) => {
    limiter.removeTokens(1, function() {
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
        hostname: 'demo.netvote.io',
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
          try{
            resolve(JSON.parse(body))
          }catch(e){
            if(body && body.indexOf("500 Server Error") > -1){
              console.error("500 error")
            } else{
              console.error("not json: "+body)
            }
            reject(e);
          }
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
    
  }).catch((e)=>{
    console.error("error occured during request")
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
    let db = firestore();
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

const getFirebaseDoc = async (collection, id) => {
  let db = firestore();
  let doc = await db.collection(collection).doc(id).get()
  if(!doc.exists){
    throw new Error("doc "+id+" does not exist")
  }
  return doc.data();
}

const getBallotGroup = async (id) => {
  return await getFirebaseDoc("ballotGroups", id)
}

const getElection = async (electionId) => {
  return await getFirebaseDoc("deployedElections", electionId)
}

const snooze = ms => new Promise(resolve => setTimeout(resolve, ms)); 

module.exports = {
  GetBallotGroup: async(id) => {
    return await getBallotGroup(id)
  },
  CreateBallotGroup: async(obj) => {
    return await netvotePost("/admin/ballotGroup", obj)
  },
  CreateBallotGroupVoter: async(groupId) => {
    return await netvoteGet("/admin/ballotGroup/"+groupId+"/voter/jwt")
  },
  AssignBallotGroupToElection: async(obj) => {
    return await netvotePost("/admin/election/ballotGroupAssignment", obj)
  },
  GetDeployedElection: async(electionId) => {
    return getElection(electionId);
  },
	CreateElection: async(obj) => {
    return await netvoteTxPost("/admin/election", obj)
  },
  GetVoteTransactions: async(electionId) => {
    return await netvoteGet(`/admin/election/${electionId}/vote/transactions`)
  },
  StopElection: async(obj) => {
    return await netvotePost("/admin/election/stop", obj)
  },
  StartElection: async(obj) => {
    return await netvotePost("/admin/election/start", obj)
  },
  ActivateElection: async(obj) => {
    return await netvoteTxPost("/admin/election/activate", obj)
  },
  GenerateVoterKeys: async(obj) => {
    return await netvotePost("/admin/election/keys", obj)
  },
  UploadVoterKeys: async(obj) => {
    return await netvotePost("/admin/election/keys/upload", obj)
  },
  GetVoterToken: async(obj, key) => {
    let res = await netvotePost("/vote/auth", obj, {
      Authorization: `Bearer ${key}`
    })
    return res.token;
  },
  GetVoterTokenForGroup: async(obj, key) => {
    let res = await netvotePost("/vote/ballotGroup/auth", obj, {
      Authorization: `Bearer ${key}`
    })
    return res.token;
  },
  CastVote: async(obj, token) => {
    return await netvoteTxPost("/vote/cast", obj, {
      Authorization: `Bearer ${token}`
    })
  },
  CheckVote: async(obj, token) => {
    return await netvotePost("/vote/check", obj, {
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
      let db = firestore();
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
