package br.com.fiap.hackaton.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import br.com.fiap.hackaton.auth.user.User;
import br.com.fiap.hackaton.auth.user.UserRepository;
import br.com.fiap.hackaton.auth.user.UserRole;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class JwksControllerTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private MockMvc mockMvc;
  @Autowired private JwtTokenService jwtTokenService;
  @Autowired private UserRepository userRepository;
  @Autowired private PublicKey jwtPublicKey;

  @Test
  void jwksEndpointExposesRsaPublicKeyAsJwkSet() throws Exception {
    mockMvc
        .perform(get("/.well-known/jwks.json"))
        .andExpect(status().isOk())
        .andExpect(header().string("Cache-Control", "public, max-age=3600"))
        .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
        .andExpect(jsonPath("$.keys[0].use").value("sig"))
        .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
        .andExpect(jsonPath("$.keys[0].kid").exists())
        .andExpect(jsonPath("$.keys[0].n").exists())
        .andExpect(jsonPath("$.keys[0].e").exists());
  }

  @Test
  void publishedJwkValidatesARealTokenWithoutThePrivateKey() throws Exception {
    User user =
        userRepository.saveAndFlush(
            new User("Renata Campos", "renata.jwks@example.com", "unused-hash", UserRole.USER));
    String token = jwtTokenService.generateToken(user);

    String responseBody =
        mockMvc
            .perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

    JwkSet jwkSet = Jwks.setParser().build().parse(responseBody);
    PublicKey parsedKey = (PublicKey) jwkSet.getKeys().iterator().next().toKey();

    var claims = Jwts.parser().verifyWith(parsedKey).build().parseSignedClaims(token).getPayload();

    assertThat(claims.get("email", String.class)).isEqualTo("renata.jwks@example.com");
  }
}
