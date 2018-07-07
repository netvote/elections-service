Elections Service APIs
======================

<img src="https://s3.amazonaws.com/netvote-docs/nv.png" alt="Logo"  height="25%" width="25%"/>

Background
-------------------
As described in the [Netvote White Paper](https://netvote.io), accepting a vote involves Authentication, Authorization, and a Vote Gateway.  For large elections (Government or otherwise), Authentication & Authorization steps will involve integrations that will vary per organization.  

This project provides a demo-ready Authentication, Authorization, and Vote Gateway built on top of Firebase.  In this simple case, any voter who provides a valid key is allowed to vote.  The admin is responsible for distributing a key to the correct voters.

Note: This project has not undergone any security audit, and should not be used to manage real elections at this time.

Election Flow
-------------------
### Election Setup
1. Create ballot metadata and post to IPFS (no API)
2. Create election with IPFS reference, and save off electionId for QR (API)
3. Create Voter Keys (via API)
4. Distribute Voter Keys in QRs (directly, no API)
5. Activate Election (if not auto-activated)

### Voting
6. Scan QR containing election electionId
7. Make selections in application
8. Scan QR containing Voter Key, exchange key for JWT Token
9. Submit vote with JWT Token

### Election End
10. Close election (via API or DApp)
11. Reveal Encryption Key (via API)
12. Tally Results in application


Voter APIs
-------------------

### POST /vote/auth

Exchange a voter key for a vote token.  The key is in place of what would normally involve showing one's ID at a polling station.  In this case, it is the Admin's reponsibility to distribute the key safely to voters who may vote.

Note:
- The vote token is currently good for one hour from exchange. 
- Another token can be requested at any time.  (The blockchain prevents duplicate voting)

Header
```
Authorization: Bearer VOTER-KEY-HERE
```

Body:
```
{
	"electionId": "electionId"
}
```
- **electionId**: (required) the electionId of the `BasicElection` contract

Returns:
```
{
	"token": "JWT-TOKEN"
}
```

### POST /vote/cast

Casts a vote for the election.  If a vote has already been cast for this voter (baked into JWT key), an update will occur (if election allows updates)

Note:
- This will validate the vote matches the ballot schema of options defined in the metadata.  (same number of options, valid choices)

Header
```
Authorization: Bearer JWT-TOKEN
```
Body:
```
{
	"vote": "base64-of-serialized-proto",
	"passphrase": "any text",
	"pushToken": "abc123"
}
```
- **vote**: (required) this is a BASE64-encoded serialized Vote message from [Vote.proto](https://github.com/netvote/elections-solidity/blob/master/protocol/vote.proto)
- **passphrase**: (optional) allows a voter to identify their vote on the blockchain without decrypting (pre-close)
- **pushToken**: (optional) API will kindly send a push message to voter when vote has been cast

Returns:
```
{"txId":"OBJECT-REFERENCE","collection":"transactionCastVote"}
```
Note: 
- The firebase collection reference can be polled for completion.  (obj.status = complete) 

Admin APIs
-------------------

### POST /admin/election

Create an election on the ethereum blockchain owned by the current firebase user UID.  Only that user may invoke other election-specific admin APIs.

Body:
```
{
	"autoActivate": true,
	"metadataLocation": "ipfs-address",
	"allowUpdates": true,
	"isPublic": true,
	"network": "ropsten or netvote"
}
```
- **autoActivate**: (optional) allow voting immediately
- **metadataLocation**: (required) electionId of ballot metadata on IPFS
- **allowUpdates**: (optional) allow voters to update their vote after the fact (enforced on chain)
- **isPublic**: (optional) generate and post the encryption key to the ballot immediately so tallying can occur during the election
- **network**: (optional) deploy to either ropsten (eth test net) or netvote (private proof-of-authority network)

Returns:
```
{"txId":"OBJECT-REFERENCE","collection":"transactionCreateElection"}
```
Note: 
- The firebase collection reference can be polled for completion.  (obj.status = complete) 

### POST /admin/election/keys

Generate voter keys for the election and return.  This will store a one-way HMAC of the key in firebase to be looked up.  

NOTE: 
- The UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.  
- The contract stores web3.sha3(uid) as the reference

Body:
```
{
	"electionId": "electionId",
	"count": 1
}
```
- **electionId**: (required) electionId of election
- **count**: (required) number of keys to create in this request

Returns:
```
["key1", "key2"...]
```

The response is the only time these keys are visible.  The admin must ensure these are delivered to voters safely and correctly.

### POST /admin/election/activate

If not already activated (via autoActivate), this will allow voting for the election.

NOTE: 
- The UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.  
- The contract stores web3.sha3(uid) as the reference

Body:
```
{
	"electionId": "electionId"
}
```
- **electionId**: (required) electionId of election

### POST /admin/election/close

This will do the following: 
1. Close the election to prevent further voting
2. Post the encryption key to the election contract to allow for vote reveal. 
3. Delete the hashing secret for the election to preserve anonymity even in full-collusion cases.

NOTE:
- This will permanently close the election (no more votes allowed).  This is irreversable.

NOTE: the UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.

Body:
```
{
	"electionId": "electionId"
}
```
- **electionId**: (required) electionId of election

### GET /admin/election/tally

This will do the following: 
1. Start a tally of the election
2. Return the firestore collection to listen on for changes.

NOTE: 
- If the election is not ready to be tallied, you'll get a 409 back

Body:
```
{
	"electionId": "electionId"
}
```
- **electionId**: (required) electionId of election

Contributing
-------------------

### Contribution Process
1. Fork repo
2. Make desired changes
3. Submit PR (Reference Issue #)
4. Reviewer will review
5. Reviewer Squash + Merges PR

License
-------
All code is released under the <a href='https://www.gnu.org/licenses/gpl-3.0.en.html'>GNU General Public License v3.0</a>.
