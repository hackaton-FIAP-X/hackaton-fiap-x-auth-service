package br.com.fiap.hackaton.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.BucketProxy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.FilterChain;

class LoginRateLimitFilterTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void allowsRequestAndContinuesChainWhenUnderLimit() throws Exception {
    BucketProxy bucket = mock(BucketProxy.class);
    when(bucket.tryConsumeAndReturnRemaining(1)).thenReturn(ConsumptionProbe.consumed(9, 0));
    ProxyManager<String> proxyManager = proxyManagerReturning(bucket);
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(() -> proxyManager, objectMapper, 10, 60);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  void rejectsWithTooManyRequestsAndRetryAfterWhenOverLimit() throws Exception {
    BucketProxy bucket = mock(BucketProxy.class);
    when(bucket.tryConsumeAndReturnRemaining(1))
        .thenReturn(
            ConsumptionProbe.rejected(
                0, TimeUnit.SECONDS.toNanos(30), TimeUnit.SECONDS.toNanos(30)));
    ProxyManager<String> proxyManager = proxyManagerReturning(bucket);
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(() -> proxyManager, objectMapper, 10, 60);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verifyNoInteractions(chain);
    assertThat(response.getStatus()).isEqualTo(429);
    assertThat(response.getHeader("Retry-After")).isEqualTo("30");
    assertThat(response.getContentAsString()).contains("Too many login attempts");
  }

  @Test
  void allowsRequestWhenProxyManagerSupplierThrows() throws Exception {
    LoginRateLimitFilter filter =
        new LoginRateLimitFilter(
            () -> {
              throw new IllegalStateException("redis unavailable");
            },
            objectMapper,
            10,
            60);
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @SuppressWarnings("unchecked")
  private ProxyManager<String> proxyManagerReturning(BucketProxy bucket) {
    ProxyManager<String> proxyManager = mock(ProxyManager.class);
    when(proxyManager.getProxy(anyString(), any())).thenReturn(bucket);
    return proxyManager;
  }
}
