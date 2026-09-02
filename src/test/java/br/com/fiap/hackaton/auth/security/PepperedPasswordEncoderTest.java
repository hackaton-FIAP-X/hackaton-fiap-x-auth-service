package br.com.fiap.hackaton.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

class PepperedPasswordEncoderTest {

  @Test
  void matchesRoundTripsThroughPepperAndArgon2id() {
    PepperedPasswordEncoder encoder =
        new PepperedPasswordEncoder(
            Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), "test-pepper-value");

    String hash = encoder.encode("MinhaSenh@123");

    assertThat(hash).startsWith("$argon2id$");
    assertThat(hash).isNotEqualTo("MinhaSenh@123");
    assertThat(encoder.matches("MinhaSenh@123", hash)).isTrue();
    assertThat(encoder.matches("SenhaErrada", hash)).isFalse();
  }

  @Test
  void differentPeppersProduceNonMatchingHashesForTheSamePassword() {
    Argon2PasswordEncoder argon2 = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    PepperedPasswordEncoder encoderWithPepperA =
        new PepperedPasswordEncoder(argon2, "pepper-a-secret");
    PepperedPasswordEncoder encoderWithPepperB =
        new PepperedPasswordEncoder(argon2, "pepper-b-secret");

    String hash = encoderWithPepperA.encode("MesmaSenha123");

    assertThat(encoderWithPepperB.matches("MesmaSenha123", hash)).isFalse();
  }
}
