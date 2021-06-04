# Identifier Attestations for Web Usage

## Outline

This document outlines a way of using attestations on an arbitrary user-unique identifier, linked to a public Ethereum address in order to facilitate sending and redeeming cheques over a blockchain, while keeping the identifier hidden. Specifically, this document describes how to do this with Ethereum using the minimal proof-of-concept demo [release jar file](https://github.com/TokenScript/attestation/releases/).

The document will first describe the overall intuition of the protocol and its security, followed by a minimal demonstration flow using demo jar file.

For information about the underlying cryptography used in the protocol, please consult this [document](https://github.com/AlphaWallet/blockchain-attestation/blob/master/use-cases/send-ether-by-identifier-attestation.md).

More specifically, this protocol considers 3 distinct parties, Alice, Bob and an Attestor (all of which can be emulated locally using demo jar file). 

Concretely we consider an issuer, Alice, who wishes to send some crypto asset to Bob, who might not have an Ethereum address. 

Alice, however, knows an identifier of Bob that can be attested to. e.g. Bob’s email address or Bob’s mobile phone number. 

Bob is able to prove that he has access to this identifier by requesting an attestation to that from an Attestor, e.g. [attestation.id](http://attestation.id).

### The Flow

Alice starts by constructing a virtual cheque (redeemable crypto asset), based on some newly sampled randomness and Bob's identifier (say his e-mail). This will result in a public riddle, cryptographically linked to Bob's identifier, and a secret solution.
 Alice posts the public riddle to a smart contract along with some ether and sends the secret solution to Bob.
 
The smart contract will pay out the ether to anyone who is able to prove that they hold the secret solution for its riddle *and* show an attestation, with a cryptographic linking to this riddle. 
 
In order to use the cheque (with a smart contract), Bob must get an attestation to his e-mail which was used in constructing the public riddle. 

For this he picks some unique and newly sampled randomness to be a secret, only known to him, which will be used in his attestation.
 
Based on Bob's secret randomness he contacts an Attester and proves to this that he has access to his email address (the one that the cheque was signed to). 

As a result, he receives a *reusable* and public attestation cryptographically constructed based on his secret randomness. 
 
Using this attestation, his own randomness and the randomness for the cheque he received from Alice, he can now redeem the cheque from the smart contract by submitting his public attestation, and a proof that he knows the secret solution to the cheque.

### Security

In order to cash the cheque Bob must both know the secret solution to its riddle *and* have an attestation that to an identifier which is *the same* that was used to construct the riddle *and* know the secret randomness he used when getting his attestation.

Because of the randomness used both in the riddle and the attestation, the identifier attested to, (email address or mobile number), can’t be learned from an observer with access to the Ethereum blockchain.

However, it will be possible for Alice to see that Bob receives cheques from other parties in the future.
The attestation can be reused in the future and anyone sending a cheque to Bob *does not* need to know anything about Bob's attestation when they construct the cheque. The only thing they need is his identifier.

The protocol is secure under the discrete log problem over the BN256 curve.

## Using demo jar file

The demo jar file contains all methods needed to run a full demo flow. It also contains methods for facilitating attestation authorization or authentication based on EIP712; see [this description](cli-attestation-demo.md) for details about that flow.

The general syntax for running a command with demo jar file is `java -jar attestation-all.jar <name-of-command>` where `name-of-command` is one of the following: `keys, create-cheque, request-attest, construct-attest, receive-cheque`. 
We discuss these commands below.

### Construct keys

The demo jar can construct SECP256k1 cryptographic keys.
This should be run by all parties.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar keys <public-key-name> <private-key-name>`

For example:

`java -jar attestation-all.jar keys pub.pem priv.pem` 

### Create Cheque

Constructs a cheque of an integer amount, to an identifier of a certain type, which will be valid for a certain amount of seconds, using a private signing key. The command outputs the public and private aspects of the cheque in two separate files.
This method should be run by Alice.
 
Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar create-cheque <amount-as-integer> <identifier> <type-of-identifier> <validity> <private-key> <public-riddle> <cheque-secret>`

- `amount-as-integer` is the amount to transfer expressed as an int, e.g. `42`.
- `identifier` is the identifier to transfer to, e.g. an email like `test@test.ts`.
- `type-of-identifier` is the type of identifier used. It *must* be either `mail` or `phone`.
- `validity` express how many seconds the cheque should be valid, e.g. `3600` for an hour.
- `private-key` is the directory of the private key used to sign the cheque and transfer the funds, e.g. `priv.pem`.
- `public-riddle` is the directory where the public part of the cheque should be placed, e.g. `cheque.pem`.
- `cheque-secret`  is the directory where the secret part of the cheque should be placed, e.g. `cheque-secret.pem`.

For example:

`java -jar attestation-all.jar create-cheque 42 test@test.ts mail 3600 priv.pem cheque.pem cheque-secret.pem`

### Request Attestation

Constructs a request for an attestation to a specific identifier of a certain type, signed using a private key. The command outputs the public attestation requests and the private attestation secret.
This method should be run by Bob.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar request-attest <private-key> <identifier> <type-of-identifier> <public-request> <request-secret>`

- `private-key` is the directory of the private key used to sign the attestation request, e.g. `priv.pem`.
- `identifier` is the identifier to transfer to, e.g. an email like `test@test.ts`.
- `type-of-identifier` is the type of identifier used. It *must* be either `mail` or `phone`.
- `public-request` is the directory where the public part of the attestation request should be placed, e.g. `request.pem`.
- `request-secret`  is the directory where the secret part of the attestation request should be placed, e.g. `request-secret.pem`.

For example:

`java -jar attestation-all.jar request-attest priv.pem test@test.ts mail request.pem request-secret.pem`

### Construct Attestation
Constructs an attestation to a specific identifier of a certain type which is valid for a certain amount of time, signed using a private key and linked to human readable name of the attestor. The command outputs the public attestation.
This method should be run by the Attestor.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar construct-attest <private-key> <attestor-name> <validity> <public-request> <attestation>`

- `private-key` is the directory of the private key used to sign the attestation, e.g. `priv.pem`.
- `attestor-name` is the name of the Attestor, e.g. `AlphaWallet`.
- `validity` expressed how many seconds the attestation should be valid, e.g. `3600` for an hour.
- `public-request` is the directory where the public part of the attestation request is placed, e.g. `request.pem`.
- `attestation`  is the directory where the attestation should be placed, e.g. `attestation.crt`.

For example:

`java -jar attestation-all.jar construct-attest priv.pem AlphaWallet 3600 request.pem attestation.crt`

### Redeem Cheque

Redeems a cheque using an attestation, its secret, the public cheque and its secret, signed using a private key.
This method should be run by Bob.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar receive-cheque <receiver-private-key> <cheque-secret> <request-secret> <public-riddle> <attestation> <attestor-public-key>`

- `receiver-private-key` is the directory of the private key used to sign the redeem request, e.g. `priv.pem`.
- `cheque-secret` is the directory where the secret part of the cheque is placed, e.g. `cheque-secret.pem`.
- `request-secret` is the directory where the secret part of the attestation request should be placed, e.g. `request-secret.pem`.
- `public-riddle` is the directory where the public part of the cheque is placed, e.g. `cheque.pem`.
- `attestation` is the directory where the attestation is placed, e.g. `attestation.crt`.
- `attestor-public-key` is the directory where the Attestor's public key is placed, e.g. `Attestor-pub.pem`

For example:

`java -jar attestation-all.jar receive-cheque priv.pem cheque-secret.pem request-secret.pem cheque.pem attestation.crt Attestor-pub.pem`

### Full local execution

To run the full protocol locally execute the following commands: 

`java -jar attestation-all.jar keys Alice-pub.pem Alice-priv.pem`

`java -jar attestation-all.jar keys Bob-pub.pem Bob-priv.pem`

`java -jar attestation-all.jar keys Attestor-pub.pem Attestor-priv.pem`

`java -jar attestation-all.jar create-cheque 42 test@test.ts mail 3600 Alice-priv.pem cheque.pem cheque-secret.pem`

`java -jar attestation-all.jar request-attest Bob-priv.pem test@test.ts mail request.pem request-secret.pem`

`java -jar attestation-all.jar construct-attest Attestor-priv.pem AlphaWallet 3600 request.pem attestation.crt`

`java -jar attestation-all.jar receive-cheque Bob-priv.pem cheque-secret.pem request-secret.pem cheque.pem attestation.crt Attestor-pub.pem`
