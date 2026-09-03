package br.com.fiap.hackaton.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.fiap.hackaton.auth.user.User;
import br.com.fiap.hackaton.auth.user.UserRepository;
import br.com.fiap.hackaton.auth.user.UserRole;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class JwtTokenServiceTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private JwtTokenService jwtTokenService;
  @Autowired private UserRepository userRepository;
  @Autowired private PublicKey jwtPublicKey;

  @Test
  void generatesTokenWithExpectedClaimsSignedWithRs256() {
    User user =
        userRepository.saveAndFlush(
            new User("Fernanda Reis", "fernanda.jwt@example.com", "unused-hash", UserRole.USER));

    String token = jwtTokenService.generateToken(user);

    var claims =
        Jwts.parser().verifyWith(jwtPublicKey).build().parseSignedClaims(token).getPayload();

    assertThat(claims.getSubject()).isEqualTo(user.getId().toString());
    assertThat(claims.get("email", String.class)).isEqualTo("fernanda.jwt@example.com");
    assertThat(claims.get("name", String.class)).isEqualTo("Fernanda Reis");
    assertThat(claims.getIssuer()).isEqualTo("fiapx-auth");

    long expirySeconds =
        (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
    assertThat(expirySeconds).isEqualTo(15 * 60);
  }
}
