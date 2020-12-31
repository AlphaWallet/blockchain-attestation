package com.alphawallet.attestation.cheque;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.text.ParseException;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class ChequeDecoder implements AttestableObjectDecoder<Cheque> {
  public ChequeDecoder() {}

  @Override
  public Cheque decode(byte[] encoding) throws IOException {
    ASN1InputStream input = new ASN1InputStream(encoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence cheque = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    long amount = (ASN1Integer.getInstance(cheque.getObjectAt(0))).getValue().longValueExact();

    ASN1Sequence validity = ASN1Sequence.getInstance(cheque.getObjectAt(1));
    ASN1GeneralizedTime notValidBeforeEnc = ASN1GeneralizedTime.getInstance(validity.getObjectAt(0));
    ASN1GeneralizedTime notValidAfterEnc = ASN1GeneralizedTime.getInstance(validity.getObjectAt(1));
    long notValidBefore, notValidAfter;
    try {
      notValidBefore = notValidBeforeEnc.getDate().getTime();
      notValidAfter = notValidAfterEnc.getDate().getTime();
    } catch (ParseException e) {
      throw new IOException("Validity is not encoded properly");
    }

    byte[] commitment = (ASN1OctetString.getInstance(cheque.getObjectAt(2))).getOctets();

    AsymmetricKeyParameter publicKey = SignatureUtility.restoreKey(DERBitString.getInstance(asn1.getObjectAt(1)).getEncoded());

    // Verify signature
    byte[] signature = DERBitString.getInstance(asn1.getObjectAt(2)).getBytes();
    return new Cheque(commitment, amount, notValidBefore, notValidAfter, signature, publicKey);
  }
}
