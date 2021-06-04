package io.alchemynft.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.demo.SmartContract;
import com.alphawallet.ethereum.AttestationReturn;
import com.alphawallet.ethereum.ERC721Token;
import com.alphawallet.token.tools.Numeric;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class NFTSmartContractTest {
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair issuerKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;
    /*
        IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, "some@mail.com" );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, issuerKeys);
     */
    static SignedIdentifierAttestation attestation;
    private SignedNFTAttestation nftAttestation;
    private final SmartContract contract = new SmartContract();
    // the URL as King Mida's public ID, plus a label (in case of twitter, the permanent numeric ID)
    static final String labeledURI = "https://twitter.com/zhangweiwu 205521676";

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG");
        rand.setSeed("seed".getBytes());
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        attestorKeys = SignatureUtility.constructECKeys(rand);
        issuerKeys = SignatureUtility.constructECKeys(rand);

        IdentifierAttestation att = new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        att.setIssuer("CN=attestation.id");
        att.setSerialNumber(1);
        assertTrue(att.checkValidity());
        attestation = new SignedIdentifierAttestation(att, attestorKeys);

        System.out.println("SubjectPublicKey's Fingerprint (summarised as Ethereum address):\n" + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @Test
    public void checkNFTSmartContract() throws Exception
    {
        ERC721Token[] myNFTs = new ERC721Token[2];
        myNFTs[0] = new ERC721Token("0xd9145CCE52D386f254917e481eB44e9943F39138", "1");
        myNFTs[1] = new ERC721Token("0xd9145CCE52D386f254917e481eB44e9943F39138", "2");

        NFTAttestation nftAtt = new NFTAttestation(attestation, myNFTs);
        //construct SignedNFTAttestation using subject key
        nftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys); // <-- signing step, NFT attestation is signed by owner of identifier, referenced below

        System.out.println("DER: " + Numeric.toHexString(nftAttestation.getDerEncoding()));

        //Extract the Ethereum signature
        byte[] sig = nftAttestation.getSignature();

        //generate NFTAttestation from the NFTAttestation bytes
        NFTAttestation nftAttestation2 = new NFTAttestation(nftAtt.getDerEncoding(), attestorKeys.getPublic());

        //check recovered signed attestation within the wrapping
        assertTrue(nftAttestation2.verify());

        //Generate SignedNFTAttestation using the reconstructed NFTAttestation and the extracted Ethereum signature
        SignedNFTAttestation signedNFTAttestation2 = new SignedNFTAttestation(nftAttestation2, subjectKeys.getPublic(), sig);
        assertTrue(signedNFTAttestation2.checkValidity());
        assertTrue(nftAttestation.checkValidity());
        assertArrayEquals(signedNFTAttestation2.getUnsignedAttestation().getDerEncoding(), nftAtt.getDerEncoding());
        assertArrayEquals(signedNFTAttestation2.getDerEncoding(), nftAttestation.getDerEncoding());

        //now check the attestation smart contract decodes this correctly
        //first verify the public attestation

        //Note that we use 'issuerKeys' address here as an unrelated address.
        // This is to test the contract correctly checks that the owner (subjectKeys) has correctly signed the wrapping NFT attestation,
        // which happens in the 'signing step' referenced above.
        // This is so a transaction need not be sent by the 'subjectKeys' account. If it is called by
        // 'subjectKeys' then the verification step is skipped since we have 'subjectKeys' signature from the ethereum transaction
        AttestationReturn atr = contract.callVerifyNFTAttestation(nftAttestation.getDerEncoding(), SignatureUtility.addressFromKey(issuerKeys.getPublic()));
        //check our return
        assertEquals(atr.identifier, labeledURI);
        assertEquals(atr.ownerAddress.toLowerCase(), SignatureUtility.addressFromKey(subjectKeys.getPublic()).toLowerCase());
        assertEquals(atr.attestorAddress.toLowerCase(), SignatureUtility.addressFromKey(attestorKeys.getPublic()).toLowerCase());
        assertTrue(atr.isValid);
        for (int index = 0; index < atr.ercToken.length; index++)
        {
            assertEquals(atr.ercToken[index].address.toString().toLowerCase(), myNFTs[index].address.toLowerCase());
            assertEquals(atr.ercToken[index].tokenId.getValue(), myNFTs[index].tokenId);
        }

        //TODO: make a more comprehensive negative test, involving bad attestation subject address etc.
        //TODO: can do this if we remove the 'isValid' check in the constructor
        byte[] attestationBytes = signedNFTAttestation2.getDerEncoding();
        //modify the signature (10th byte from end will be within the signature)
        attestationBytes[attestationBytes.length - 10] = (byte)(attestationBytes[attestationBytes.length - 10] + 0x01);

        atr = contract.callVerifyNFTAttestation(attestationBytes, SignatureUtility.addressFromKey(issuerKeys.getPublic()));
        assertFalse(atr.isValid); //should fail
        atr = contract.callVerifyNFTAttestation(attestationBytes, SignatureUtility.addressFromKey(subjectKeys.getPublic()));
        assertTrue(atr.isValid); //should pass, because we don't need to check the wrapping signature is valid if it's sent by the subjectKey
    }

}
