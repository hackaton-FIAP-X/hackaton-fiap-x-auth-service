package br.com.fiap.hackaton.auth.security;

import br.com.fiap.hackaton.auth.user.User;
import io.jsonwebtoken.Jwts;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

  private static final String ISSUER = "fiapx-auth";
  private static final Duration EXPIRATION = Duration.ofMinutes(15);

  private final PrivateKey privateKey;

  public JwtTokenService(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public String generateToken(User user) {
    Instant now = Instant.now();

    return Jwts.builder()
        .subject(user.getId().toString())
        .claim("email", user.getEmail())
        .claim("name", user.getName())
        .issuer(ISSUER)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(EXPIRATION)))
        .signWith(privateKey, Jwts.SIG.RS256)
        .compact();
  }
}
