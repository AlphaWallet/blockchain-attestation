# What is an attestation

An attestation is a signed claim by an attester. For example, a marriage certificate is an attestation to attest the marriage.

Attestations are useful on the web. For example, an email address attestation helps the website to be sure that the user owns the email address without having to resort to sending email verification code.

And it is useful on the blockchain. For example, an ICO contract could be written in a way that only attested investors could participate in the early rounds. A financial advisor can sign such attestation. In the `use-cases` directory there is an example of allowing one to redeem either using an identifier attestation. It enables the scenario like "Alice sends Bob 𝑥 amount of Ether without knowing Bob's Ethereum address (but Bob's identifier like email address)."

Attestation can also serve the purpose of blockchain Token. For example, a FIFA ticket, a non-fungible token in Ethereum terms. A smart contract can be made to work with such attestations, for example, allowing one to be transferred to a new Etheruem address.

Attestations are issued off-chain and used on-chain.

# Everything nowadays is on the blockchain, why off-chain?

Off-chain is essential for two reasons.

First, attestations carry private information. For example, in the case of identity attestations, the birth date; in the case of mobile phone warranty, the IMEI number of the phone purchased. Such private information, if leaked on the blockchain, will have a financial consequence (e.g. scams).

Second, attestations are often too trivial to justify a paid transaction. For example, an attestation that a video game player has killed 100 enemies with a knife. A real world example of this would be a voucher that can be redeemed for a coffee; such attestations exist outside of any blockchain, but may eventually lead to its use on the blockchain. As in the previous example, when the badge of 100 knife kills entitles the player a discount to buy a pre-sale sequel from a smart-contract.

# Why attestations?

Attestations are ideal for identifying purposes. An individual's identity can't exist on the blockchain because the concept encompasses too much information and obligations, but an attestation can testify an aspect of identity. Such attestations are issued on the subject's public keys. Age attestation and driving capacity attestation are two good examples of such identity attestations.

Attestations are also a perfect way to solve the blockchain chicken-and-egg problem. Very often, in the early stages, services can't provide blockchain-only solutions. The FIFA world cup, for example, can issue blockchain tickets, but they can't mandate payment with Ether. The situation is similar to the early stage of the Internet, FIFA would find it easier to only accept credit card payment, but that denies blockchain advantages like atomic transactions for second-hand tickets (a pivotal measurement to prevent fake tickets). In such cases, tickets as attestations can be converted to non-fungible tokens if the issuer allows so by writing the corresponding smart-contracts. For example, FIFA world cup tickets can be issued as attestations and users would convert them to non-fungible tokens when they see the need to resell the tickets. FIFA does not need to maintain a blockchain connection at the point of sale.

# ERC publications

This repo is a work on progress and has been organised into the following ERC's

[ERC1386](https://github.com/ethereum/EIPs/issues/1386), [ERC1387](https://github.com/ethereum/EIPs/issues/1387) & [ERC1388](https://github.com/ethereum/EIPs/issues/1388)

# organisation of this repository

This repository has the following content:

paper
: the paper behind the design of this project. To read it, get the PDF from releases tab: https://github.com/alpha-wallet/ethereum-attestation/releases

ethereum/lib
: lib for smart contracts which uses attestations

ethereum/issuers
: example smart contracts used by issuers, for example, revocation list management.

ethereum/trustlist
: members of trustlists to be adopted by smart contracts

ethereum/experiments
: work not in the published specifications

ethereum/example-james-squire
: an example to be used in your projects which requires attestations


# Donations
If you support the cause, we could certainly use donations to help fund development:

0xbc8dAfeacA658Ae0857C80D8Aa6dE4D487577c63
