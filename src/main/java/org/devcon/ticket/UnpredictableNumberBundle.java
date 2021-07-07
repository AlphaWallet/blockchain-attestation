package org.devcon.ticket;


import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "number", "randomness", "domain", "expiration"})
public class UnpredictableNumberBundle {
  private String number;
  private byte[] randomness;
  private String domain;
  private long expiration;

  public UnpredictableNumberBundle() {}

  public UnpredictableNumberBundle(String number, byte[] randomness, String domain, long expiration) {
    this.number = number;
    this.randomness = randomness;
    this.domain = domain;
    this.expiration = expiration;
  }

  public String getNumber() {
    return number;
  }

  public void setNumber(String number) {
    this.number = number;
  }

  public byte[] getRandomness() {
    return randomness;
  }

  public void setRandomness(byte[] randomness) {
    this.randomness = randomness;
  }
  public String getDomain() {
    return domain;
  }

  public void setDomain(String domain) {
    this.domain = domain;
  }

  public long getExpiration() {
    return expiration;
  }

  public void setExpiration(long expiration) {
    this.expiration = expiration;
  }
}
