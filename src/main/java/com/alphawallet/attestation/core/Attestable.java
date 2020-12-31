package com.alphawallet.attestation.core;

public interface Attestable extends ASNEncodable, Verifiable, Validateable {
  public byte[] getCommitment();
}
