package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class UnpredictableNumberToolTest {
  private static final String DOMAIN = "http://www.hotel-bogota.com";
  private static byte[] macKey;
  private static SecureRandom rand;

  @Mock
  UnpredictableNumberBundle mockedUn;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    macKey = rand.generateSeed(16);
  }

  @BeforeEach
  public void makeUn() {
    MockitoAnnotations.initMocks(this);

    Mockito.when(mockedUn.getDomain()).thenReturn(DOMAIN);
    Mockito.when(mockedUn.getExpiration()).thenReturn(Long.MAX_VALUE);
    Mockito.when(mockedUn.getRandomness()).thenReturn(new byte[UnpredictableNumberTool.BYTES_IN_SEED]);
    Mockito.when(mockedUn.getNumber()).thenReturn("abcdefghijk");
  }

  @Test
  public void sunshine() {
    UnpredictableNumberTool unt = new UnpredictableNumberTool(macKey, DOMAIN);
    assertEquals(DOMAIN, unt.getDomain());
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    assertTrue(unt.validateUnpredictableNumber(un.getNumber(), un.getRandomness(), un.getExpiration()));
  }

  @Test
  public void invalidDomain() {
    assertThrows(IllegalArgumentException.class, ()-> new UnpredictableNumberTool(macKey, "NotaDomain"));
  }

  @Test
  public void expired() {
    // expired jan 1, 1970
    Mockito.when(mockedUn.getExpiration()).thenReturn(0L);
    UnpredictableNumberTool unt = new UnpredictableNumberTool(macKey, DOMAIN);
    assertFalse(unt.validateUnpredictableNumber(mockedUn.getNumber(), mockedUn.getRandomness(), mockedUn.getExpiration()));
  }

  @Test
  public void wrongUnt() {
    UnpredictableNumberTool unt = new UnpredictableNumberTool(macKey, DOMAIN);
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    assertTrue(unt.validateUnpredictableNumber(un.getNumber(), un.getRandomness(), un.getExpiration()));
    UnpredictableNumberTool wrongUnt = new UnpredictableNumberTool(macKey, "http://www.other-domain.com");
    assertFalse(wrongUnt.validateUnpredictableNumber(un.getNumber(), mockedUn.getRandomness(), un.getExpiration()));
    UnpredictableNumberTool otherWrongUnt = new UnpredictableNumberTool(rand.generateSeed(16), DOMAIN);
    assertFalse(otherWrongUnt.validateUnpredictableNumber(un.getNumber(), mockedUn.getRandomness(), un.getExpiration()));
  }
}
