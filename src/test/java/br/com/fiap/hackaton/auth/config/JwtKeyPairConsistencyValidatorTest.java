package br.com.fiap.hackaton.auth.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

class JwtKeyPairConsistencyValidatorTest {

  @Test
  void doesNotThrowWhenKeysFormAMatchingPair() throws NoSuchAlgorithmException {
    KeyPair keyPair = generateRsaKeyPair();
    var validator =
        new JwtKeyPairConsistencyValidator(keyPair.getPrivate(), keyPair.getPublic());

    assertThatCode(() -> validator.run(null)).doesNotThrowAnyException();
  }

  @Test
  void throwsWhenKeysDoNotFormAMatchingPair() throws NoSuchAlgorithmException {
    KeyPair keyPairA = generateRsaKeyPair();
    KeyPair keyPairB = generateRsaKeyPair();
    var validator =
        new JwtKeyPairConsistencyValidator(keyPairA.getPrivate(), keyPairB.getPublic());

    assertThatThrownBy(() -> validator.run(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("do not form a matching RSA key pair");
  }

  private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }
}
