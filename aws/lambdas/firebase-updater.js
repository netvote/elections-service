const google = require('googleapis');
const rp = require('request-promise');

const getCredential = async() => {
    const key = require('./key.json');
    const jwtClient = new google.google.auth.JWT({
        email: key.client_email,
        key: key.private_key,
        scopes: ['https://www.googleapis.com/auth/datastore']
    });

    return await jwtClient.authorize();
}

module.exports = {

    createDoc: async(collection, id, obj) => {
        let credential = await getCredential();
        let options = {
            method: 'POST',
            uri: 'https://firestore.googleapis.com/v1beta1/projects/netvote2/databases/(default)/documents/'+collection+"?documentId="+id,
            body: {
                fields: obj
            },
            headers: {
                Authorization: "Bearer "+credential.access_token
            },
            json: true
        };
        
        await rp(options);
    },

    updateStatus: async(doc, updates, completeTime) => {
        if(!doc){
            console.log("skipping updateStatus, no callback specified");
            return;
        }

        let updateMask = completeTime ? "updateMask.fieldPaths=completeTime": "";

        let fields = completeTime ? {
            completeTime: {
                integerValue: new Date().getTime()
            }
        } : {}


        for (var key in updates) {
            if (updates.hasOwnProperty(key)) {
                if (updateMask !== "") {
                    updateMask += "&"
                }
                updateMask += "updateMask.fieldPaths="+key
                fields[key] = {
                    stringValue: updates[key]
                }
            }
        }

        let credential = await getCredential();

        let options = {
            method: 'PATCH',
            uri: 'https://firestore.googleapis.com/v1beta1/projects/netvote2/databases/(default)/documents/'+doc+"?"+updateMask,
            body: {
                fields: fields
            },
            headers: {
                Authorization: "Bearer "+credential.access_token
            },
            json: true
        };

        try{
            await rp(options);
        }catch(e){
            console.error("error while posting callback, ignoring", e)
        }
    }
}
