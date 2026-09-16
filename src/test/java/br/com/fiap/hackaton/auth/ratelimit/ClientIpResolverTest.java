package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ClientIpResolverTest {

  @Test
  void usesFirstIpFromForwardedForHeaderWhenPresent() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Forwarded-For", "203.0.113.5, 10.0.0.2");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("203.0.113.5");
  }

  @Test
  void trimsWhitespaceAroundForwardedForIp() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Forwarded-For", "  203.0.113.5  ,10.0.0.2");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("203.0.113.5");
  }

  @Test
  void fallsBackToRemoteAddrWhenHeaderAbsent() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRemoteAddr("192.168.1.10");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("192.168.1.10");
  }

  @Test
  void fallsBackToRemoteAddrWhenHeaderBlank() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Forwarded-For", "   ");
    request.setRemoteAddr("192.168.1.10");

    assertThat(ClientIpResolver.resolve(request)).isEqualTo("192.168.1.10");
  }
}
