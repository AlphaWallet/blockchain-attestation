package com.alphawallet.attestation.core;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.Keccak.Digest256;

public class SignatureUtility {
    /**
     * Extract the ECDSA SECP256K1 public key from its DER encoded BITString
     * @param input
     * @return
     */
    public static AsymmetricKeyParameter restoreKey(byte[] input) throws IOException {
        AlgorithmIdentifier identifierEnc = new AlgorithmIdentifier(new ASN1ObjectIdentifier(
            AttestationCrypto.OID_SIGNATURE_ALG), AttestationCrypto.ECDSACurve.toASN1Primitive());
        return restoreKey(identifierEnc, input);
    }

    /**
     * Extract any public key from its DER encoded BITString and AlgorithmIdentifier
     * @param input
     * @return
     */
    public static AsymmetricKeyParameter restoreKey(AlgorithmIdentifier identifier, byte[] input) throws IOException {
        ASN1BitString keyEnc = DERBitString.getInstance(input);
        ASN1Sequence spkiEnc = new DERSequence(new ASN1Encodable[] {identifier, keyEnc});
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiEnc);
        return PublicKeyFactory.createKey(spki);
    }

    /**
     * Constructs a DER encoded, non-malleable deterministic ECDSA signature.
     * That is, n accordance with EIP 2 (the y-coordinate is guaranteed to be <n/2).
     * The deterministic approach used is the one from RFC 6979
     * @param toSign
     * @param key
     * @return
     */
    public static byte[] signDeterministic(byte[] toSign, AsymmetricKeyParameter key) {
        Digest keccak = new KeccakDigest(256);
        keccak.update(toSign, 0, toSign.length);
        HMacDSAKCalculator randomnessProvider = new HMacDSAKCalculator(keccak);
        byte[] digest = new byte[256/8];
        keccak.doFinal(digest, 0);
        ECDSASigner signer = new ECDSASigner(randomnessProvider);
        signer.init(true, key);
        BigInteger[] signature = signer.generateSignature(digest);
        return normalizeAndEncodeSignature(signature, ((ECKeyParameters) key).getParameters());
    }

    /**
     * Constructs a DER encoded interministic (randomized) ECDSA signature based on an already hashed value.
     * Despite being randomized this is done in accordance with EIP 2 (the y-coordinate is guaranteed to be <n/2)
     * @param digest The digest to sign
     * @param key The key to use for signing.
     * @return
     */
    public static byte[] signHashedRandomized(byte[] digest, AsymmetricKeyParameter key) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, key);
        BigInteger[] signature = signer.generateSignature(digest);
        return normalizeAndEncodeSignature(signature, ((ECKeyParameters) key).getParameters());
    }

    private static byte[] normalizeAndEncodeSignature(BigInteger[] signature, ECDomainParameters params) {
        try {
            // Normalize number s
            BigInteger half_curve = params.getCurve().getOrder().shiftRight(1);
            if (signature[1].compareTo(half_curve) > 0) {
                signature[1] = params.getN().subtract(signature[1]);
            }
            ASN1EncodableVector asn1 = new ASN1EncodableVector();
            asn1.add(new ASN1Integer(signature[0]));
            asn1.add(new ASN1Integer(signature[1]));
            return new DERSequence(asn1).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(byte[] unsigned, byte[] signature, AsymmetricKeyParameter key) {
        Digest256 digest = new Keccak.Digest256();
        byte[] digestBytes = digest.digest(unsigned);
        return verifyHashed(digestBytes, signature, key);
    }

    static boolean verifyHashed(byte[] digest, byte[] signature, AsymmetricKeyParameter key) {
        try {
            ASN1InputStream input = new ASN1InputStream(signature);
            ASN1Sequence seq = ASN1Sequence.getInstance(input.readObject());
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            // Normalize number s
            BigInteger half_curve = ((ECKeyParameters) key).getParameters().getCurve().getOrder().shiftRight(1);
            if (s.compareTo(half_curve) > 0) {
                s = ((ECKeyParameters) key).getParameters().getN().subtract(s);
            }
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, key);
            return signer.verifySignature(digest, r, s);
        } catch (Exception e) {
            // Something went wrong so the signature cannot be verified
           return false;
        }
    }
}
