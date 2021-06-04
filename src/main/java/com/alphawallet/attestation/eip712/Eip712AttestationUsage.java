package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.UseAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.JsonEncodable;

/**
 * Class for asserting and validating that a user who already has an Identifier Attestation wishes to
 * use it at a given website. The assertion is linked to a public key, which can be used to validate
 * future future communication from the user, up until a user-approved expiration time.
 *
 * Note that this object leaks the user's Identifier Attestation (Ethereum Public key) and
 * the user's identifier to the webserver.
 */
public class Eip712AttestationUsage extends Eip712Validator implements JsonEncodable, Verifiable,
    TokenValidateable {
  private static final Logger logger = LogManager.getLogger(Eip712AttestationUsage.class);

  public static final int PLACEHOLDER_CHAIN_ID = 0;

  private final long maxTokenValidityInMs;
  private final UseAttestation useAttestation;
  private final AttestationUsageData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter userPublicKey;

  public Eip712AttestationUsage(String attestorDomain, String identifier, UseAttestation useAttestation, AsymmetricKeyParameter signingKey) {
    this(attestorDomain, Timestamp.DEFAULT_TOKEN_TIME_LIMIT,  PLACEHOLDER_CHAIN_ID, identifier, useAttestation, signingKey);
  }

  public Eip712AttestationUsage(String attestorDomain, long maxTokenValidityInMs, long chainId,
      String identifier, UseAttestation useAttestation, AsymmetricKeyParameter signingKey) {
    super(attestorDomain, new Eip712AttestationUsageEncoder(chainId));
    try {
      this.maxTokenValidityInMs = maxTokenValidityInMs;
      this.useAttestation = useAttestation;
      this.jsonEncoding = makeToken(identifier, useAttestation, signingKey);
      this.userPublicKey = retrieveUserPublicKey(jsonEncoding, AttestationUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationUsageData.class);
    } catch (Exception e ) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not encode asn1"));
    }
    constructorCheck();
  }

  public Eip712AttestationUsage(String attestorDomain, AsymmetricKeyParameter attestationIssuerVerificationKey,
      String jsonEncoding) {
    this(attestorDomain, attestationIssuerVerificationKey, Timestamp.DEFAULT_TOKEN_TIME_LIMIT, PLACEHOLDER_CHAIN_ID,
        jsonEncoding);
  }

  public Eip712AttestationUsage(String attestorDomain, AsymmetricKeyParameter attestationIssuerVerificationKey,
      long maxTokenValidityInMs, long chainId, String jsonEncoding) {
    super(attestorDomain, new Eip712AttestationUsageEncoder(chainId));
    try {
      this.maxTokenValidityInMs = maxTokenValidityInMs;
      this.jsonEncoding = jsonEncoding;
      this.userPublicKey = retrieveUserPublicKey(jsonEncoding, AttestationUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationUsageData.class);
      this.useAttestation = new UseAttestation(URLUtility.decodeData(data.getPayload()), attestationIssuerVerificationKey);
    } catch (Exception e ) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not decode asn1"));
    }
    constructorCheck();
  }

  void constructorCheck() throws IllegalArgumentException {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify object"));
    }
  }

  String makeToken(String identifier, UseAttestation useAttestation,
      AsymmetricKeyParameter signingKey) throws IOException {
    Eip712Issuer issuer = new Eip712Issuer<AttestationUsageData>(signingKey, encoder);
    String encodedUseAttestation = URLUtility.encodeData(useAttestation.getDerEncoding());
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + maxTokenValidityInMs);
    AttestationUsageData data = new AttestationUsageData(
        encoder.getUsageValue(), identifier, encodedUseAttestation, now, expirationTime);
    return issuer.buildSignedTokenFromJsonObject(data, domain);
  }

  private boolean proofLinking() {
    BigInteger candidateExponent = AttestationCrypto.mapToCurveMultiplier(getType(), getIdentifier());
    ECPoint commitmentPoint = AttestationCrypto.decodePoint(getAttestation().getUnsignedAttestation().getCommitment());
    ECPoint candidateRiddle = commitmentPoint.subtract(AttestationCrypto.G.multiply(candidateExponent));
    if (!candidateRiddle.equals(getPok().getRiddle())) {
      logger.error("Could not validate proof linking to attestation commitment");
      return false;
    }
    return true;
  }

  public String getIdentifier() {
    return data.getIdentifier();
  }

  public AsymmetricKeyParameter getUserPublicKey() {
    return userPublicKey;
  }

  public FullProofOfExponent getPok() {
    return useAttestation.getPok();
  }

  public AttestationType getType() {
    return useAttestation.getType();
  }

  public SignedIdentifierAttestation getAttestation() {
    return useAttestation.getAttestation();
  }

  public AsymmetricKeyParameter getSessionPublicKey() {
    return useAttestation.getSessionPublicKey();
  }

  @Override
  public String getJsonEncoding() {
    return jsonEncoding;
  }

  @Override
  public boolean checkTokenValidity() {
    long nonceMinTime = Timestamp.stringTimestampToLong(data.getExpirationTime()) - maxTokenValidityInMs;
    long nonceMaxTime = Timestamp.stringTimestampToLong(data.getExpirationTime());
    if (!useAttestation.checkValidity()) {
      logger.error("Not not validate underlying object");
      return false;
    }
    if (!data.getDescription().equals(encoder.getUsageValue())) {
      logger.error("Description field incorrect");
      return false;
    }
    Timestamp time = new Timestamp(data.getTimestamp());
    time.setValidity(maxTokenValidityInMs);
    if (!time.validateAgainstExpiration(Timestamp.stringTimestampToLong(data.getExpirationTime()))) {
      logger.error("Timestamp not valid");
      return false;
    }
    if (!SignatureUtility.verifyKeyAgainstAddress(
        userPublicKey, useAttestation.getAttestation().getUnsignedAttestation().getAddress())) {
      logger.error("Could not verify signature");
      return false;
    }
    if (!Nonce.validateNonce(useAttestation.getPok().getNonce(),
        (useAttestation.getAttestation().getUnsignedAttestation()).getAddress(), domain, new Timestamp(nonceMinTime), new Timestamp(nonceMaxTime))) {
      logger.error("Nonce validation failed");
      return false;
    }
    if (!proofLinking()) {
      logger.error("Could not verify proof linking");
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!useAttestation.verify()) {
      logger.error("Could not verify underlying UseAttestation object");
      return false;
    }
    return true;
  }
}
