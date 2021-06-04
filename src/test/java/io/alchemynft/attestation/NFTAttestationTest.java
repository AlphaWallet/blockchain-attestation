package io.alchemynft.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.demo.SmartContract;
import com.alphawallet.ethereum.ERC721Token;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class NFTAttestationTest {
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
    static final String labeledURI = "https://twitter.com/king_midas";

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG");
        rand.setSeed("seed".getBytes());
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        attestorKeys = SignatureUtility.constructECKeys(rand);
        issuerKeys = SignatureUtility.constructECKeys(rand);

        IdentifierAttestation att = new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        assertTrue(att.checkValidity());
        attestation = new SignedIdentifierAttestation(att, attestorKeys);

        System.out.println("SubjectPublicKey's Fingerprint (summarised as Ethereum address):\n" + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @Test
    public void testNFTAttestation() throws Exception
    {
        ERC721Token[] myNFTs = new ERC721Token[2];
        myNFTs[0] = new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25");
        myNFTs[1] = new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26");

        NFTAttestation nftAtt = new NFTAttestation(attestation, myNFTs);
        //construct SignedNFTAttestation using subject key
        nftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        Path p = Files.createTempFile("unsigned_nftAttestation", ".der");

        System.out.println("To check the unsigned NFT attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, nftAttestation.getDerEncoding());

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
    }

    @Test
    public void testPublicAttestation() {
        assertTrue(attestation.checkValidity());
        assertTrue(attestation.verify());
        assertTrue(SignatureUtility.verifyEthereumSignature(attestation.getUnsignedAttestation().getPrehash(), attestation.getSignature(), attestorKeys.getPublic()));
    }

    @Test
    public void testDecoding() throws Exception {
        IdentifierAttestation att = HelperTest.makeMaximalAtt(subjectKeys.getPublic());
        SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, issuerKeys);
        assertTrue(SignatureUtility.verifyEthereumSignature(att.getPrehash(), signed.getSignature(), issuerKeys.getPublic()));
        assertArrayEquals(att.getPrehash(), signed.getUnsignedAttestation().getPrehash());
        byte[] signedEncoded = signed.getDerEncoding();

        SignedIdentifierAttestation newSigned = new SignedIdentifierAttestation(signedEncoded, issuerKeys.getPublic());
        assertArrayEquals(signed.getDerEncoding(), newSigned.getDerEncoding());
    }
}
