# Shard backup validator

## Overview

This document provides a critical analyses of the current state practices in MPC backup and recovery techniques, specifically, the fireblocks recovery tool. Detailing the current state process employed by fireblocks, we examine the key challenges and areas of opportunity in the methods and approaches used in the fireblocks recovery tool. Then, we proceed to explain in detail the proposed solution, updated codebase, and employing the property of zero knowledge to address the challenges and concerns. Additionally, we outline the next steps for enhancing the prototype and enabling a long term viable solution.

## Business case

Clients (custody providers, key managers, etc.) use MPC wallets to protect their assets. In the business as usual scenario, clients' keys are custodied by custodians, and the keys provide access and control over digital assets owned by the clients. As a security practice, custodians employ MPC techniques to protect the client keys in order to provide an extra layer of security and prevent single point of attack/failure. Custodians break up the keys into multiple shards and are distributed to different entities. Most implementations of backup and associated testing are prone to multiple vulnerabilities for which MPC is intended to prevent (e.g., single point of abuse).  Hence, clients take additional and un-necessary risks to perform wallet backups.

## Fireblocks recovery process (Current State)

Fireblocks recovery process is an MPC based technique to backup shards of 3 different entities by combining the shards to validate the combined ownership of the keys in a 3-of-3 MPC model. All 3 shards are required to be joined/combined for a successful validation against the wallet public key, that is custodied by Fireblocks on behalf of the customers.

### Inputs

* Backup file `<backup.zip>` containing:
    * `metadata.json`
        * keys {`public_key`, `algorithm`}
        * `chaincode` signifying the type of wallet and used to get `xPub` from `public_key`
        * `tenantId`
    * 2 pem files encrypting shards (corresponding to 2 different servers, identified by a `tenantId`)
    * 1 Mobile encrypted shard file
* Private key `<priv.pem>` used to generate all addresses and keys
* Passphrase used for encrypting the server shards
* Passphrase used for encrypting mobile shard

### Process of recovery
1. Extract `backup.zip` contents
1. Decrypt `priv.pem` to obtain RSA public and private keys:
    1. This codebase uses RSA based cryptography to encrypt data using asymmetric encryption
    1. Using the passphrase for server shards, import the key using the RSA module to retrieve public key points (`n`, `e`), private key points (`d`, `p`, `q`) to satisfy `p * q = n`, where `n` is the order of the underlying ECDSA curve
    1. Obtain `cipher` using `OAEP` to apply one time padding
1. Parse `metadata.json` to get the and `chaincode` in bytes and  `public_key` needed for validation
1. Decrypt the server and mobile shard files using the `cipher` to obtain individual decrypted shards
:warning: All encrypted files are decrypted in one place - a single point of "abuse" and reliance on the effective governance and trust in conducting the decryption in a "box"
1. Compute the lagrangian polynomial, by evaluating the term per each of the 3 entities in play and adding the results: 
    1. Calculate identity using `utils.recover.get_player_id` for the server shards and `deviceId` for the mobile shard
    1. Calculate the coefficient corresponding to each entity
    1. Evaluate the term, `value` (the decrypted shard) `*` `coefficient`
    1. Add all the terms
    Note: The arithmetic operations used for the above computations are to modular arithmetic based evaluated using `mod n`, where `n` is the order of the curve
1. Validate the equality of the public and private key values agains the public key value in `metadata.json`
1. Recover the extended public and private keys using the public key and chaincode values in `metadata.json`

### Challenges with the recovery model
:warning: All shards are brought together into one place, to prove that the backups are effective for recovery. This is a single point of "abuse" by exposing access to encrypted backup shards if compromised. Once exposed in this manner, this is the same as the funds guarded by the `xPub` in the MPC solution
:warning: System does not give the ability to be dynamic over time on access and recovery. Who can open the backup is fixed, in this case, 3 fixed entities
:warning: In the event of loss of any of the shards due to any disasters or unavailability the recovery process is mooted and a new process is to be initiated
:warning: If a person leaves, they possess some knowledge of the underlying recovery model

## Proposed Solution

The proposed solution is a backup methodology providing:
1. Process for a secure encrypted backup
1. Ability for an entity to self confirm that the entity has the secrets to conduct recovery
1. Ability for a custodian to prove to other entities (e.g. regulatory audits) of recovery of the encrypted shards
1. Ability to be dynamic over time on who/how (m-of-n) many can access secret information and are able to do a recovery process

### Requirements
To protect against a loss of wallet address and private keys due to technological or service provider failure 
  * Requires a backup of an institution’s MPC wallet’s key or quorum of shard
  * Backup must be testable without exposing the institution to new risks - (preferred) the institution can prove to a third party that the institution has knowledge of the keys without revealing any secret information

### WSL Prototype Solution Implementation

Identify individual entities as provers (`P`), and a separate entity as the verifier (`V`). Provers are to prove the knowledge of the keys without revealing the secret shares. Using public information (witness) from provers, verifiers validate the possession of the shards by the collective set of all entities.

We use the following notations to denote the operations that follow:
* `G`: generator point
* `s_i`: secret of entity shard `i`, where `i = 3`
* `L_i`: lagrange coefficient of entity shard `i`
* `r_i`: random number chosen by entity `i`
* `k`: lagrange sum

#### Assumptions

1. A key requirement is for all the provers to know the individual identities of all other provers. This is done in the code using `utils.recover.retrieve_identities(backup.zip)`, to calculate identities by using the `utils.recover.get_player_id` for server shards and `deviceId` for mobile shards
1. Process of communication of witness values is assumed to be a manual process for the scope of the prototype. As a long term consideration, the communication can be via point to point communication modes, or on a decentralized ledger such as IPFS or public EVM compatible chains
1. The generator point `G` is pre-chosen and made public to provers and verifiers

#### Process
1. `P` gathers inputs needed to invoke the `split_secret_cli` module:
    * `shard`: shard file of the entity `i`
    * `mobile`: flag to determine whether the type is a mobile shard
    * `metadata`: metadata file containing key metadata
    * `priv`: private pem file of the entity `i` (only for server shards)
1. `P` computes their individual shard witness value: `s_i * L_i`
    1. Given that all provers know other identities, `L_i` is computed to get the lagrange coefficient
    1. Witness value is evaluated: `s_i * L_i * G`
1. `P` shares the witness value with `V`. For the purposes of the PoC, this value is written to a local file
1. `V` combines the individual witness values and validates, `k = sum over c_i * L_i * G = public_key * G` using `utils.recover.combine_validate()` where `public_key` is extracted from the `metadata.json` file

In principle this process can be extended as follows:

1. `P` chooses a random number `r_i`, and publishes `r_i * G`
1. `P` runs a one time pad function by evaluating `c_i = r_i + (s_i * L_i) mod order(G)`, and publishes `c_i`
1. `V` computes `Z = sum over r_i * G`
1. `V` computes `Y = sum over c_i`
1. `V` verifies:
    * `Y = sum over r_i, k * G`
    * `Y/Z = k * G` or the `public_key` from the metadata file

### Run the utility locally
* As a prover, `./split_secret_cli.py --shard <PATH_TO_SHARD> --mobile <TRUE/FALSE> --metadata <PATH_TO_METADATA> --priv <PATH_TO_SERVER_PRIV_KEY>
* As a verifier, `./combine_and_validate.py --output <PATH_TO_OUTPUT> --metadata <PATH_TO_METADATA>
