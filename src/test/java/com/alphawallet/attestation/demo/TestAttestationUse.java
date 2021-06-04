package com.alphawallet.attestation.demo;


import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.tools.Numeric;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.devcon.ticket.Ticket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.abi.datatypes.Address;

public class TestAttestationUse {
    private static final String MAIL = "test@test.ts";
    private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
    private static final int TICKET_CLASS = 0;  // Regular ticket
    private static final int CONFERENCE_ID = 6;
    private static final BigInteger TICKET_SECRET = new BigInteger("48646");
    private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair ticketIssuerKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;
    private static AttestationCrypto crypto;
    private SignedIdentifierAttestation attestation;
    private AttestedObject<Ticket> attestedTicket;
    private final SmartContract contract = new SmartContract();

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG");
        rand.setSeed("seed".getBytes());

        crypto = new AttestationCrypto(rand);
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        attestorKeys = SignatureUtility.constructECKeys(rand);
        ticketIssuerKeys = SignatureUtility.constructECKeys(rand);

        System.out.println("Issuer Key Address: " +  SignatureUtility.addressFromKey(attestorKeys.getPublic()));
        System.out.println("Subject Key Address: " +  SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @BeforeEach
    public void makeAttestedCheque()
    {
        IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
        attestation = new SignedIdentifierAttestation(att, attestorKeys);
    }

    @Test
    public void testSendAttestation() {
        // *** PRINT DER ENCODING OF OBJECTS ***
        try {
            byte[] attestationData = attestation.getDerEncoding();

            String subjectAddress = SignatureUtility.addressFromKey(subjectKeys.getPublic());
            String attestorAddress = SignatureUtility.addressFromKey(attestorKeys.getPublic());

            System.out.println("Attestation: " + Numeric.toHexString(attestationData));
            System.out.println("PreHash: " + Numeric.toHexString(attestation.getUnsignedAttestation().getDerEncoding()));

            //Test smart contract decodes the attestation and verifies the content correctly
            //call smart contract to recover subject and attestor key ethereum addresses.
            List<Address> contractAddresses = contract.getAttestationAddresses(attestation);

            assertTrue(contractAddresses.size() == 2);

            System.out.println("Subject address from contract: " + contractAddresses.get(0));
            System.out.println("Attestor address from contract: " + contractAddresses.get(1));

            assertTrue(contractAddresses.get(0).toString().equalsIgnoreCase(subjectAddress));
            assertTrue(contractAddresses.get(1).toString().equalsIgnoreCase(attestorAddress));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
