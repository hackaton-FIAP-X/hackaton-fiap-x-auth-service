package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class CurrentUserIdArgumentResolverTest {

  private final CurrentUserIdArgumentResolver resolver = new CurrentUserIdArgumentResolver();

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void supportsUuidParameterAnnotatedWithCurrentUserId() throws NoSuchMethodException {
    MethodParameter parameter = annotatedParameter();

    assertThat(resolver.supportsParameter(parameter)).isTrue();
  }

  @Test
  void doesNotSupportParameterWithoutTheAnnotation() throws NoSuchMethodException {
    Method method = SampleController.class.getMethod("withoutAnnotation", UUID.class);
    MethodParameter parameter = new MethodParameter(method, 0);

    assertThat(resolver.supportsParameter(parameter)).isFalse();
  }

  @Test
  void resolvesUuidFromTheAuthenticatedJwtSubject() throws Exception {
    UUID userId = UUID.randomUUID();
    Jwt jwt = mock(Jwt.class);
    when(jwt.getSubject()).thenReturn(userId.toString());
    SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(jwt, null));

    UUID resolved = resolver.resolveArgument(annotatedParameter(), null, null, null);

    assertThat(resolved).isEqualTo(userId);
  }

  @Test
  void throws401WhenThereIsNoAuthentication() {
    assertThatThrownBy(() -> resolver.resolveArgument(annotatedParameter(), null, null, null))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("401");
  }

  private static MethodParameter annotatedParameter() throws NoSuchMethodException {
    Method method = SampleController.class.getMethod("withAnnotation", UUID.class);
    return new MethodParameter(method, 0);
  }

  static class SampleController {
    public void withAnnotation(@CurrentUserId UUID userId) {}

    public void withoutAnnotation(UUID userId) {}
  }
}
