This project has demonstrative use of blockchain attestations.

## Roles:

## Build Demo.jar

Build with gradle:

    $ gradle shadowJar

Check Demo.jar is built:

    $ ls ./build/libs/Demo.jar
    
## Prepare

Construct keys for all roles. Three roles are involved.

Issuer
: Someone who issues a crypto asset to the user redeemable by its identifier (e.g. email address)

Attester
: An organisation which validates an identifier of the user.

Beneficiary
: The recipient of the crypto asset.

Commands:

    $ java -jar build/libs/Demo.jar keys issuer-pub.pem issuer.pem
    $ java -jar build/libs/Demo.jar keys attester-pub.pem attester.pem
    $ java -jar build/libs/Demo.jar keys beneficiary-pub.pem beneficiary.pem

## Demo

### The Issuer Issues

Issuer issues a cheque (redeemable asset) by:

    $ java -jar build/libs/Demo.jar create-cheque 42 test@test.ts mail 3600 issuer.pem cheque.pem cheque-secret.pem

This creates two files, `cheque.pem`, `cheque-secret.pem`. Both are passed to the beneficiary.

### The Beneficiary requests an identifier attestation

    $ java -jar build/libs/Demo.jar request-attest beneficiary.pem test@test.ts mail request.pem request-secret.pem
    
### The Attester constructs an attestation

    $ java -jar build/libs/Demo.jar construct-attest attester.pem AlphaWallet 3600 request.pem attestation.crt

### The Beneficiary redeems (use) the cheque (asset)

    $ java -jar build/libs/Demo.jar receive-cheque beneficiary.pem cheque-secret.pem request-secret.pem cheque.pem attestation.crt attester-pub.pem


