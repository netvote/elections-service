const assert = require('assert');
const nv = require('../netvote-request');
const nvEncoder = require('../netvote-signatures')
const metadataLocation = 'QmZaKMumAXXLkHPBV1ZdAVsF4XCUYz1Jp5PY3oEsLrKoy6';

const toVotePayload = async (electionId, voteObj, requireProofs) => {
    let vbase64 = await nvEncoder.encodeVote(voteObj, requireProofs);
    let payload = {
      electionId: electionId,
      vote: vbase64
    }
    if(requireProofs){
      payload.proof =  await nvEncoder.signVote(vbase64);
    }
    return payload;
}

const expectResult = (res, candidate, votes) => {
    assert.equal(res[candidate], votes, `${candidate} should have ${votes} votes`);
}  

const TEST_NETWORK = "netvote"

const snooze = (ms) => { 
    console.log("sleeping "+ms)
    return new Promise(resolve => setTimeout(resolve, ms)); 
}
  
const VOTE_0_0_0 = {
    ballotVotes: [
      {
          choices: [
              {
                  selection: 0
              },
              {
                  selection: 0
              },
              {
                  selection: 0
              }
          ]
      }
    ]
  }


describe(`Ballot Groups`, function() {

    let groupId;
    let electionId;
    let voterToken;
    let voteToken;
    let deployedElection;

    let ballotGroup = {
        name: "Test Ballot Group",
        active: true
    }

    let options = {
        'name': 'ballot group election',
        'isPublic' : true,
        'requireProof': false,
        'metadataLocation': metadataLocation,
        'allowUpdates': true,
        'autoActivate': true,
        'network': TEST_NETWORK
    }

    it('should create election', async () => {
        let res = await nv.CreateElection(options);
        deployedElection = await nv.GetDeployedElection(res.electionId);
        electionId = res.electionId;
        console.log("ElectionID: "+electionId);
    })

    it('should create ballot group', async () => {
        let bg = await nv.CreateBallotGroup(ballotGroup);
        assert.equal(bg.id != null, true, "expected id not to be null")
        groupId = bg.id;
        console.log("GroupID: "+groupId);
    })

    it('should create jwt key for group', async () => {
        let jwt = await nv.CreateBallotGroupVoter(groupId);
        assert.equal(jwt != null, true, "expected jwt not to be null")
        voterToken = jwt.token;
    })

    it('should assign ballot group to election', async()=>{
        let res = await nv.AssignBallotGroupToElection({
            groupId: groupId,
            electionId: electionId,
            shortCode: "abc123"
        });
        assert.equal(res.status, "ok", "expected ok status");
    })

    it('should exchange voter jwt for vote jwt', async()=>{
        let token = await nv.GetVoterTokenForGroup({
            shortCode: "ABC123"
        }, voterToken);

        assert.equal(token != null, true, "expected non null token");
        voteToken = token;
    })

    it('should cast vote', async() =>{
        let payload1 = await toVotePayload(electionId, VOTE_0_0_0, false);
        let tx1 = await nv.CastVote(payload1, voteToken)
        assert.equal(tx1.status, "complete")
    })

    it('should tally election correctly', async()=>{
        if(TEST_NETWORK === "mainnet"){
            await snooze(30000)
        }
        const result = await nv.TallyElection(electionId);
        const ballotTotal = result.ballots[deployedElection.address].totalVotes;
        assert.equal(ballotTotal, 1, "expected 1 vote");
        const ballotResults = result.ballots[deployedElection.address].results['ALL'];
        expectResult(ballotResults[0], "John Smith", 1)
        expectResult(ballotResults[0], "Sally Gutierrez", 0)
        expectResult(ballotResults[0], "Tyrone Williams", 0)
        expectResult(ballotResults[1], "Yes", 1)
        expectResult(ballotResults[1], "No", 0)
        expectResult(ballotResults[2], "Doug Hall", 1)
        expectResult(ballotResults[2], "Emily Washington", 0)
    })

});
