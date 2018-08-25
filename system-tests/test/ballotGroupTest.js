const assert = require('assert');
const nv = require('../netvote-request');

let ballotGroup = {
    name: "Test Ballot Group",
    active: true
}

const metadataLocation = 'QmZaKMumAXXLkHPBV1ZdAVsF4XCUYz1Jp5PY3oEsLrKoy6';

describe(`Ballot Groups`, function() {

    let groupId;
    let electionId;

    before(async() => {
        let options = {
            'name': 'election with signature verification',
            'isPublic' : true,
            'requireProof': false,
            'metadataLocation': metadataLocation,
            'allowUpdates': true,
            'autoActivate': true,
            'network': "netvote"
        }
        let res = await nv.CreateElection(options);
        electionId = res.electionId;
    });

    it('should create ballot group', async () => {
        let bg = await nv.CreateBallotGroup(ballotGroup);
        assert.equal(bg.id != null, true, "expected id not to be null")
        groupId = bg.id;
    })

    it('should create jwt key for group', async () => {
        let jwt = await nv.CreateBallotGroupVoter(groupId);
        assert.equal(jwt != null, true, "expected jwt not to be null")
        console.log(JSON.stringify(jwt));
    })

    it('should assign ballot group to election', async()=>{
        let res = await nv.AssignBallotGroupToElection({
            groupId: groupId,
            electionId: electionId,
            shortCode: "abc123"
        });
    })

});