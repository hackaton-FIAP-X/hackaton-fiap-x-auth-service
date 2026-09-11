package br.com.fiap.hackaton.security.commons;

import java.util.UUID;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class SubjectIsUuidValidator implements OAuth2TokenValidator<Jwt> {

  private static final OAuth2Error INVALID_SUBJECT =
      new OAuth2Error("invalid_token", "The sub claim must be a user UUID", null);

  @Override
  public OAuth2TokenValidatorResult validate(Jwt token) {
    String subject = token.getSubject();
    if (subject == null || subject.isBlank()) {
      return OAuth2TokenValidatorResult.failure(INVALID_SUBJECT);
    }
    try {
      UUID.fromString(subject);
      return OAuth2TokenValidatorResult.success();
    } catch (IllegalArgumentException invalidUuid) {
      return OAuth2TokenValidatorResult.failure(INVALID_SUBJECT);
    }
  }
}
