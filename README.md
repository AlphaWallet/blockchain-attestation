This project has demonstrative use of blockchain attestations.

## Roles:

Three roles are involved.

Issuer
: Someone who issues a crypto asset to the user redeemable by its identifier (e.g. email address)

ID attester
: An organisation which validates an identifier of the user.

User
: The beneficiary of the crypto asset.

## Demonstration

As an example, the user is identified with `my@example.com` and their ethereum address is `0xdecafbad…`.

In all cases, the private keys are pre-coded inside the demonstration classes.

### Issuing of the asset

Issuer runs:

    $ java -jar … my.class.name my@example.com > asset.der
    
    Issuer public key: 0x8038930802938
    User identifier: my@example.com
    Asset Cheque (redeembable) written to the output.

### Issuing of the identifier attestation

The user runs this:

    $ java -jar … my.class.name > req.csr
    CSR written to the output - now you can send it to the attester.
    
This generates a request to get the attestation and save it as req.csr. It is passed to the attester which runs this:

    $ java -jar … my.class.name req.csr > id_att.der
    Issuer public key: 0x8038930802938
    User identifier: my@example.com
    Identifier attestation written to the output.

### Use of the asset

Let's say the user wishes to access a function which requires the user having the crypto asset. Let's say it's `redeem()`.

    $ java -jar … call.function.with.attestation --id=id_att.der --asset=asset.der my_example_smart_contract.redeem()
    Smart contract says "yes".


