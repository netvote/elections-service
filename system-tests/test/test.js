const assert = require('assert');
const nv = require('../netvote-request');

const metadataLocation = 'QmZaKMumAXXLkHPBV1ZdAVsF4XCUYz1Jp5PY3oEsLrKoy6';
const VOTE_1_1_1 = 'CLlgEgwKAggBCgIIAQoCCAE=';
const VOTE_0_0_0 = 'CLlgEgwKAggACgIIAAoCCAA=';

const expectResult = (res, candidate, votes) => {
  assert.equal(res[candidate], votes, `${candidate} should have ${votes} votes`);
}

describe(`End to End Election`, function() {

  let scenarios = [
    {
      'name': 'private election with manual activation',
      'isPublic' : false,
      'metadataLocation': metadataLocation,
      'allowUpdates': true,
      'autoActivate': false,
      'network': 'netvote'
    },
    {
      'name': 'public election with auto activation',
      'isPublic' : true,
      'metadataLocation': metadataLocation,
      'allowUpdates': true,
      'autoActivate': true,
      'network': 'netvote'
    },
  ]

  scenarios.forEach((options) => {

    describe(options.name, function() {
      let deployedElection;
      let electionId;
      let keys;
      let tokens;
      let txIds = [];

      it('should create election', async () => {
        let res = await nv.CreateElection(options);
        let deployedElection = await nv.GetDeployedElection(res.electionId);
        assert.equal(deployedElection.network, options.network)
        let expectedStatus = options.autoActivate ? 'voting' : 'building'
        assert.equal(deployedElection.status, options.autoActivate ? 'voting' : 'building', `expected ${expectedStatus} status`)
        assert.equal(deployedElection.resultsAvailable, options.isPublic)
        electionId = res.electionId;
      });

      if(!options.autoActivate) {
        it('should manually activate election', async()=>{
          await nv.ActivateElection({
            electionId: electionId
          });
          deployedElection = await nv.GetDeployedElection(electionId);
          assert.equal(deployedElection.status, 'voting')
        })
      }

      it('should generate voter keys', async()=>{
        keys = await nv.GenerateVoterKeys({
          electionId: electionId,
          count: 3
        });
        assert.equal(keys.length, 3)
      })

      it('should get three voter tokens', async()=>{
        let token1 = await nv.GetVoterToken({
          electionId: electionId
        }, keys[0])
        let token2 = await nv.GetVoterToken({
          electionId: electionId
        }, keys[1])
        let token3 = await nv.GetVoterToken({
          electionId: electionId
        }, keys[2])

        tokens = [token1, token2, token3]
      })

      it('should cast three votes', async()=>{
        let tx1 = await nv.CastVote({
          electionId: electionId,
          vote: VOTE_0_0_0
        }, tokens[0])
        let tx2 = await nv.CastVote({
          electionId: electionId,
          vote: VOTE_0_0_0
        }, tokens[1])
        let tx3 = await nv.CastVote({
          electionId: electionId,
          vote: VOTE_0_0_0
        }, tokens[2])

        // save off first for retrieval later
        txIds.push(tx1.tx)

        assert.equal(tx1.status, "complete")
        assert.equal(tx2.status, "complete")
        assert.equal(tx3.status, "complete");
      })

      it('should update two votes', async()=>{
        let token1 = await nv.GetVoterToken({
          electionId: electionId
        }, keys[1])
        let token2 = await nv.GetVoterToken({
          electionId: electionId
        }, keys[2])

        // change to vote_1_1_1
        let tx2 = await nv.CastVote({
          electionId: electionId,
          vote: VOTE_1_1_1
        }, token1)
        let tx3 = await nv.CastVote({
          electionId: electionId,
          vote: VOTE_1_1_1
        }, token2)

        // save off for retrieval later
        txIds.push(tx2.tx)
        txIds.push(tx3.tx)

        assert.equal(tx2.status, "complete")
        assert.equal(tx3.status, "complete");
      })

      it('should close election', async()=>{
        await nv.CloseElection({
          electionId: electionId
        });
        deployedElection = await nv.GetDeployedElection(electionId);
        assert.equal(deployedElection.status, 'closed')
        assert.equal(deployedElection.resultsAvailable, true)
      })

      it('should tally election correctly', async()=>{
        const result = await nv.TallyElection(electionId);
        const ballotTotal = result.ballots[deployedElection.address].totalVotes;
        assert.equal(ballotTotal, 3, "expected 3 votes");
        const ballotResults = result.ballots[deployedElection.address].results['ALL'];
        expectResult(ballotResults[0], "John Smith", 1)
        expectResult(ballotResults[0], "Sally Gutierrez", 2)
        expectResult(ballotResults[0], "Tyrone Williams", 0)
        expectResult(ballotResults[1], "Yes", 1)
        expectResult(ballotResults[1], "No", 2)
        expectResult(ballotResults[2], "Doug Hall", 1)
        expectResult(ballotResults[2], "Emily Washington", 2)
      })

      it('should lookup votes correctly', async()=>{
        let res1 = await nv.LookupVote(electionId, txIds[0])
        let ballotResults = res1.ballots[deployedElection.address].results['ALL'];
        expectResult(ballotResults[0], "John Smith", 1)
        expectResult(ballotResults[0], "Sally Gutierrez", 0)
        expectResult(ballotResults[0], "Tyrone Williams", 0)
        expectResult(ballotResults[1], "Yes", 1)
        expectResult(ballotResults[1], "No", 0)
        expectResult(ballotResults[2], "Doug Hall", 1)
        expectResult(ballotResults[2], "Emily Washington", 0)

        let res2 = await nv.LookupVote(electionId, txIds[1])
        ballotResults = res2.ballots[deployedElection.address].results['ALL'];
        expectResult(ballotResults[0], "John Smith", 0)
        expectResult(ballotResults[0], "Sally Gutierrez", 1)
        expectResult(ballotResults[0], "Tyrone Williams", 0)
        expectResult(ballotResults[1], "Yes", 0)
        expectResult(ballotResults[1], "No", 1)
        expectResult(ballotResults[2], "Doug Hall", 0)
        expectResult(ballotResults[2], "Emily Washington", 1)

        let res3 = await nv.LookupVote(electionId, txIds[2])
        ballotResults = res3.ballots[deployedElection.address].results['ALL'];
        expectResult(ballotResults[0], "John Smith", 0)
        expectResult(ballotResults[0], "Sally Gutierrez", 1)
        expectResult(ballotResults[0], "Tyrone Williams", 0)
        expectResult(ballotResults[1], "Yes", 0)
        expectResult(ballotResults[1], "No", 1)
        expectResult(ballotResults[2], "Doug Hall", 0)
        expectResult(ballotResults[2], "Emily Washington", 1)
      })

    });

  })
});

describe.skip(`Throughput Test`, function() {
  let electionId;
  let keys = [];

  let scenarios = [
    {
      name: 'election with 250 votes',
      isPublic : true,
      metadataLocation: metadataLocation,
      allowUpdates: true,
      autoActivate: true,
      network: 'netvote',
      votes: 250,
      maxTime: 500000
    }
  ]

  scenarios.forEach((options) => {
    it('should create election', async () => {
      let res = await nv.CreateElection(options);
      let deployedElection = await nv.GetDeployedElection(res.electionId);
      assert.equal(deployedElection.network, options.network)
      let expectedStatus = options.autoActivate ? 'voting' : 'building'
      assert.equal(deployedElection.status, options.autoActivate ? 'voting' : 'building', `expected ${expectedStatus} status`)
      assert.equal(deployedElection.resultsAvailable, options.isPublic)
      electionId = res.electionId;
    });

    it('should generate voter keys', async()=>{
      let votesLeft = options.votes;
      let batch = 100;
      while(votesLeft > 0){
        let thisBatch = (votesLeft < batch) ? votesLeft : batch;
        let k = await nv.GenerateVoterKeys({
          electionId: electionId,
          count: thisBatch
        });
        votesLeft -= thisBatch;
        keys = keys.concat(k)
      }
      assert.equal(keys.length, options.votes)
    })

    it('should cast '+options.votes+' votes', async()=> {
      let votePromises = [];
      for(let i=0; i<options.votes; i++){
        let key = keys[i];
        let index = i;
        votePromises.push(new Promise(async (resolve, reject)=>{
          let token = await nv.GetVoterToken({
            electionId: electionId
          }, key)
          let start = new Date().getTime();
          await nv.CastVoteAsync({
            electionId: electionId,
            vote: VOTE_0_0_0
          }, token)
          let end = new Date().getTime();
          resolve(true);
        }))
      }
      await Promise.all(votePromises);
    })

    const snooze = ms => new Promise(resolve => setTimeout(resolve, ms)); 
    const now = () => new Date().getTime() 

    it('should tally election correctly', async()=>{
      let deployedElection = await nv.GetDeployedElection(electionId);
      let ballotTotal = 0;
      let result;
      let startTime = new Date().getTime();
      let elapsed = 0;
      while(ballotTotal != options.votes && elapsed < options.maxTime){
        result = await nv.TallyElection(electionId);
        ballotTotal = result.ballots[deployedElection.address].totalVotes;
        console.log(`votes: ${ballotTotal}, time: ${elapsed/1000}s`)
        if(ballotTotal != options.votes){
          await snooze(5000)
          elapsed = now() - startTime;
        }
      }
      assert.equal(ballotTotal, options.votes, "expected votes = "+options.votes);
      const ballotResults = result.ballots[deployedElection.address].results['ALL'];
      expectResult(ballotResults[0], "John Smith", options.votes)
      expectResult(ballotResults[0], "Sally Gutierrez", 0)
      expectResult(ballotResults[0], "Tyrone Williams", 0)
      expectResult(ballotResults[1], "Yes", options.votes)
      expectResult(ballotResults[1], "No", 0)
      expectResult(ballotResults[2], "Doug Hall", options.votes)
      expectResult(ballotResults[2], "Emily Washington", 0)
    })


  })

})
