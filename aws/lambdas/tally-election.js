const firebaseUpdater = require("./firebase-updater.js");
const networks = require("./eth-networks.js");

const tally = require("@netvote/elections-tally");
const updateEveryNVotes = process.env.UPDATE_EVERY_N_VOTES ? parseInt(process.env.UPDATE_EVERY_N_VOTES) : 100;

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;
    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let version = event.version ? event.version : 15;
        let validateSignatures = !!(event.validateSignatures);
        let address = event.address;
        let nv = await networks.NetvoteProvider(event.network);
        if(!address){
            throw new Error("must specify address in event")
        }

        let counter = 0;
        let badVotes = [];
    
        let result = await tally.tallyElection({
            electionAddress: address,
            version: version,
            provider: nv.ethUrl(),
            validateSignatures: validateSignatures,
            resultsUpdateCallback: async (res) => {
                counter++;
                if(counter % updateEveryNVotes == 0){
                    await firebaseUpdater.updateStatus(event.callback, {
                        status: "tallying",
                        progress: JSON.stringify(res.progress),
                        results: JSON.stringify(res.result)
                    }, true);
                }
            },
            badVoteCallback: async (obj)=>{
                console.warn("BADVOTE:"+JSON.stringify(obj))
                badVotes.push(obj);
                await firebaseUpdater.updateStatus(event.callback, {
                    badVotes: JSON.stringify(badVotes)
                }, true);
            }
        })
    

        console.log("result: "+JSON.stringify(result))

        await firebaseUpdater.updateStatus(event.callback, {
            status: "complete",
            results: JSON.stringify(result)
        }, true);
        callback(null, "ok")
        
    } catch (e){
        console.error("error while tallying: ", e);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        callback(e, "ok")
    }
};
