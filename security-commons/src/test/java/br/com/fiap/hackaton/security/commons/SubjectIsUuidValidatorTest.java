package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class SubjectIsUuidValidatorTest {

  private final SubjectIsUuidValidator validator = new SubjectIsUuidValidator();

  @Test
  void succeedsWhenSubjectIsAValidUuid() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn("3fa85f64-5717-4562-b3fc-2c963f66afa6");

    assertThat(validator.validate(jwt).hasErrors()).isFalse();
  }

  @Test
  void failsWhenSubjectIsNotAUuid() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn("not-a-uuid");

    assertThat(validator.validate(jwt).hasErrors()).isTrue();
  }

  @Test
  void failsWhenSubjectIsBlank() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn("  ");

    assertThat(validator.validate(jwt).hasErrors()).isTrue();
  }

  @Test
  void failsWhenSubjectIsNull() {
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn(null);

    assertThat(validator.validate(jwt).hasErrors()).isTrue();
  }
}
