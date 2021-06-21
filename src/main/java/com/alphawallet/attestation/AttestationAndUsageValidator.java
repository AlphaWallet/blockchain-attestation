package com.alphawallet.attestation;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.TokenValidateable;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.ECPoint;

public class AttestationAndUsageValidator implements TokenValidateable, Verifiable {
  private static final Logger logger = LogManager.getLogger(AttestationAndUsageValidator.class);

  private final UseAttestation useAttestation;
  private final String identifier;
  private final AsymmetricKeyParameter userPublicKey;

  public AttestationAndUsageValidator(UseAttestation useAttestation,
      String identifier, AsymmetricKeyParameter userPublicKey) {
    this.useAttestation = useAttestation;
    this.identifier = identifier;
    this.userPublicKey = userPublicKey;
  }

  public UseAttestation getUseAttestation() {
    return useAttestation;
  }

  public String getIdentifier() {
    return identifier;
  }

  public AsymmetricKeyParameter getUserPublicKey() {
    return userPublicKey;
  }

  private boolean proofLinking() {
    BigInteger candidateExponent = AttestationCrypto.mapToCurveMultiplier(useAttestation.getType(), identifier);
    ECPoint commitmentPoint = AttestationCrypto.decodePoint(useAttestation.getAttestation().getUnsignedAttestation().getCommitment());
    ECPoint candidateRiddle = commitmentPoint.subtract(AttestationCrypto.G.multiply(candidateExponent));
    if (!candidateRiddle.equals(useAttestation.getPok().getRiddle())) {
      logger.error("Could not validate proof linking to attestation commitment");
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

  @Override
  public boolean checkTokenValidity() {
    if (!useAttestation.checkValidity()) {
      logger.error("Could not validate underlying object");
      return false;
    }
    if (!SignatureUtility.verifyKeyAgainstAddress(
        userPublicKey, useAttestation.getAttestation().getUnsignedAttestation().getAddress())) {
      logger.error("Could not verify signature");
      return false;
    }
    if (!proofLinking()) {
      logger.error("Could not verify proof linking");
      return false;
    }
    return true;
  }
}
