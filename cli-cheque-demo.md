# Attestations Facilitating Cheques (redeemable crypto-assets) on Blockchain

## Outline

This document outlines a way of using attestations on an arbitrary user-unique identifier, linked to a public Ethereum address in order to facilitate authorization linking to an ephemeral public key. 
This can for example be used do silent, web-based authentication/account sign-on in a way where a user is not just linked to their email, but also their Ethereum account. 
When using SubtleCrypto to handle the ephemeral keys this allows for both highly secure, and convenient account management on the web with an efficient link to Ethereum. 
Despite this flow showing how use an attestation, this could be generalized (with minor code additions) for work for any other type of token.

The code for this project is available [here](https://github.com/TokenScript/attestation/releases/).

This document will first describe the overall intuition of the protocol and its security, followed by a minimal demonstration flow using demo jar file.

More specifically, this protocol considers 3 distinct parties, a user, a website and an Attestor (all of which can be emulated locally using demo jar file). 

Concretely we consider a user that wishes to construct an attestation to their email address and prove to a website that it has control of the attestation (thus indirectly authenticating with a linking to their email and Ethereum address).
To do so, the user must prove that they have access to their email and the Ethereum address in question. This is done by by requesting an attestation from an Attestor, e.g. [attestation.id](http://attestation.id).

### The Flow

The user starts by requesting an attestation to their e-mail, linked to their Ethereum address.
This is done by the user constructing a Pedersen commitment to their email and signing this with their Ethereum key. 
The signed commitment is passed to the Attestor along with a proof that it knows an opening of the commitment to their email and the Attestor verifies the user indeed controls this email.
Optionally the user can also include an ephemeral public key in the attestation request to the Attestor. 

After the Attestor has verified the request it issues a signed attestation to the user, similar to an x509 certificate.
If an ephemeral key was included in the attestation, the user can then hand the website the attestation request along with the signed attestation and a signature/encryption to any message it wishes using the ephemeral key.
If no ephemeral key was included in the attestation the user constructs a *usage* request which includes the signed attestation, a proof that it knows the opening to its Pedersen commitment, context information (such as identity of the website it wants to access) and an ephemeral public key. 
The user signs the usage request using it Ethereum key and sends this to the website along with a signature/encryption to any message it wishes using the ephemeral key.

For future access to the website it is not necessary for the user to sign anything with its Ethereum key and thus signing/encryption of messages can happen silently using SubtleCrypto. 

### Security

The user can *only* get an attestation if they control the claimed Ethereum key and email address.
A compromised attestor will of course be able to impersonate a user with a specific email, but unable to do so for a user with a specific Ethereum address.

The website will not be able to impersonate a user on any other website.

Any third party who sees an attestation will not be able to see the user's mail, nor will such a third party even be able to brute-force it.
However, anyone seeing a *usage* request will learn the user's email. The same is the case for an attestation including an ephemeral key. 
Furthermore, for an attestation request including an ephemeral key we note that if the private counter-part should be learned by a third party it will be able to impersonate the user at *any* website supporting this flow. 
However, if a *usage* request was used, it would only be able to impersonate the user at the specific website which the usage request was for.

The protocol is secure under the discrete log problem over the BN256 curve.

## Using demo jar file

The demo jar file contains all methods needed to run a full demo flow.

The general syntax for running a command with demo jar file is `java -jar attestation-all.jar <name-of-command>` where `name-of-command` is one of the following: `keys, request-attest, construct-attest, use-attest, request-attest-and-usage, sign-message, and verify-usage`. 
We discuss these commands below.

### Construct keys

The demo jar can construct SECP256k1 cryptographic keys.
This should be run by all parties.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar keys <public-key-name> <private-key-name>`

For example:

`java -jar attestation-all.jar keys pub.pem priv.pem` 

### Request Attestation

Constructs an Eip712 request for an attestation to a specific identifier of a certain type, signed using a private key. The command outputs the public attestation request and the randomness used in the Pedersen commitment.
This method should be run by the user.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar request-attest <private-key> <identifier> <type-of-identifier> <request> <request-secret>`

- `private-key` is the directory of the private key used to sign the attestation request, e.g. `priv.pem`.
- `identifier` is the identifier of the user, e.g. an email like `test@test.ts`.
- `type-of-identifier` is the type of identifier used. It *must* be either `mail` or `phone`.
- `request` is the directory where the public part of the attestation request should be placed, e.g. `request.json`.
- `request-secret`  is the directory where the secret part of the attestation request should be placed, e.g. `request-secret.pem`.

For example:

`java -jar attestation-all.jar request-attest priv.pem test@test.ts mail request.json request-secret.pem`

### Request Attestation with Usage
Constructs a combined attestation and usage Eip712 request for an attestation to a specific identifier of a certain type along with an ephemeral key, signed using a private key. The command outputs the public attestation request and the randomness used in the Pedersen commitment.
The request can later function as a usage request towards *any* server for the attestation-to-be-constructed.
This method should be run by the user.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar request-attest-and-usage <private-key> <identifier> <type-of-identifier> <private-session-key> <request> <request-secret>`

- `private-key` is the directory of the private key used to sign the attestation request, e.g. `priv.pem`.
- `identifier` is the identifier of the user, e.g. an email like `test@test.ts`.
- `type-of-identifier` is the type of identifier used. It *must* be either `mail` or `phone`.
- `private-session-key` is the directory where the ephemeral private key should be placed, e.g. `session-priv.pem`
- `request` is the directory where the public part of the combined attestation and usage request should be placed, e.g. `request.json`.
- `request-secret`  is the directory where the secret part of the attestation request should be placed, e.g. `request-secret.pem`.

For example:

`java -jar attestation-all.jar request-attest-and-usage priv.pem test@test.ts mail session-priv.pem request.json request-secret.pem`

### Construct Attestation
Constructs an attestation from an attestation request to a specific identifier of a certain type which is valid for a certain amount of time, signed using a private key and linked to human readable name of the attestor. The command outputs the public attestation.
This method should be run by the Attestor.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar construct-attest <Attestor-private-key> <attestor-name> <validity> <request> <attestation>`

- `Attestor-private-key` is the directory of the private key used to sign the attestation, e.g. `Attestor-priv.pem`.
- `attestor-name` is the name of the Attestor, e.g. `AlphaWallet`.
- `validity` expressed how many seconds the attestation should be valid, e.g. `3600` for an hour.
- `request` is the directory where the public part of the attestation request is placed, e.g. `request.json`.
- `attestation`  is the directory where the attestation should be placed, e.g. `attestation.crt`.

For example:

`java -jar attestation-all.jar construct-attest Attestor-priv.pem AlphaWallet 3600 request.json attestation.crt`

### Construct Attestation from Attestation and Usage Request
Constructs an attestation from a combined attestation-and-usage request to a specific identifier of a certain type which is valid for a certain amount of time, signed using a private key and linked to human readable name of the attestor. The command outputs the public attestation.
This method should be run by the Attestor.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar construct-attest-and-usage <Attestor-private-key> <attestor-name> <validity> <request> <attestation>`

- `Attestor-private-key` is the directory of the private key used to sign the attestation, e.g. `Attestor-priv.pem`.
- `attestor-name` is the name of the Attestor, e.g. `AlphaWallet`.
- `validity` expressed how many seconds the attestation should be valid, e.g. `3600` for an hour.
- `request` is the directory where the public part of the combined attestation and usage request is placed, e.g. `request.json`.
- `attestation`  is the directory where the attestation should be placed, e.g. `attestation.crt`.

For example:

`java -jar attestation-all.jar construct-attest-and-usage Attestor-priv.pem AlphaWallet 3600 request.json attestation.crt`

### Use Attestation

Constructs an Eip712 *usage* request using an attestation, its secret, the public verification key of the attestor, and identifier information of the user
This method should be run by the user.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar use-attest <private-key> <attestation> <request-secret> <public-attestor-key> <identifier> <type-of-identifier> <private-session-key> <request>`

- `private-key` is the directory of the private key used to sign the usage request, e.g. `priv.pem`.
- `attestation` is the directory where the attestation is placed, e.g. `attestation.crt`.
- `request-secret` is the directory where the secret part of the attestation request should is placed, e.g. `request-secret.pem`.
- `attestor-public-key` is the directory where the Attestor's public key is placed, e.g. `Attestor-pub.pem`
- `identifier` is the identifier of the user, e.g. an email like `test@test.ts`.
- `type-of-identifier` is the type of identifier used. It *must* be either `mail` or `phone`.
- `private-session-key` is the directory where the ephemeral private key should be placed, e.g. `session-priv.pem`
- `request` is the directory where the usage request should be placed, e.g. `request.json`.

For example:

`java -jar attestation-all.jar use-attest priv.pem attestation.crt request-secret.pem Attestor-pub.pem test@test.ts mail session-priv.pem request.json`

### Sign Message

Constructs a signed message based on ephemeral keys.
This method should be run by the user.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar sign-message <private-session-key> <message> <siganture>`

- `private-session-key` is the directory where the ephemeral private key is placed, e.g. `session-priv.pem`.
- `message` is the message to sign, e.g. `"some sort of message"`.
- `signature` is the directory where the signature on the message should be placed, e.g. `signature.bin`.

For example:

`java -jar attestation-all.jar sign-message session-priv.pem "some sort of message" signature.bin`

### Verify Usage of combined Attestation and Usage Request

Verifies the signature on a message and validates the ephemeral key against a combined attestation and usage request and an attestation.
This method should be run by the website.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar verify-attest-and-usage <request> <attestation> <attestor-public-key> <message> <signature>`

- `request` is the directory where the *usage* request or attestation with ephemeral key is placed, e.g. `request.json`.
- `attestation` is the directory where the attestation is placed, e.g. `attestation.crt`.
- `attestor-public-key` is the directory where the Attestor's public key is placed, e.g. `Attestor-pub.pem`
- `message` is the message to sign, e.g. `"some sort of message"`.
- `signature` is the directory where the signature on the message is placed, e.g. `signature.bin`.

For example:

`java -jar attestation-all.jar verify-attest-and-usage request.json attestation.crt Attestor-pub.pem "some sort of message" signature.bin`

### Verify Usage

Verifies the signature on a message and validates the ephemeral key against a *usage* request. 
This method should be run by the website.

Specifically the syntax of the command is as follows:

`java -jar attestation-all.jar verify-usage <request> <attestor-public-key> <message> <signature>`

- `request` is the directory where the *usage* request is placed, e.g. `request.json`.
- `attestor-public-key` is the directory where the Attestor's public key is placed, e.g. `Attestor-pub.pem`
- `message` is the message to sign, e.g. `"some sort of message"`.
- `signature` is the directory where the signature on the message is placed, e.g. `signature.bin`.

For example:

`java -jar attestation-all.jar verify-usage request.json Attestor-pub.pem "some sort of message" signature.bin`

### Full local execution

To run the full protocol locally execute the following commands: 

1. `java -jar attestation-all.jar keys pub.pem priv.pem`

2. `java -jar attestation-all.jar keys Attestor-pub.pem Attestor-priv.pem`

3. Either:
 
* `java -jar attestation-all.jar request-attest priv.pem test@test.ts mail request.json request-secret.pem`

* `java -jar attestation-all.jar construct-attest Attestor-priv.pem AlphaWallet 3600 request.json attestation.crt`
  
* `java -jar attestation-all.jar use-attest priv.pem attestation.crt request-secret.pem Attestor-pub.pem test@test.ts mail session-priv.pem request.json`

* `java -jar attestation-all.jar sign-message session-priv.pem "some sort of message" signature.bin`

* `java -jar attestation-all.jar verify-usage request.json Attestor-pub.pem "some sort of message" signature.bin`
   
3. Or just:

* `java -jar attestation-all.jar request-attest-and-usage priv.pem test@test.ts mail session-priv.pem request.json request-secret.pem`

* `java -jar attestation-all.jar construct-attest-and-usage Attestor-priv.pem AlphaWallet 3600 request.json attestation.crt`

* `java -jar attestation-all.jar sign-message session-priv.pem "some sort of message" signature.bin`

* `java -jar attestation-all.jar verify-attest-and-usage request.json attestation.crt Attestor-pub.pem "some sort of message" signature.bin`
