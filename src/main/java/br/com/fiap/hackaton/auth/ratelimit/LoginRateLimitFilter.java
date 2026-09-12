package br.com.fiap.hackaton.auth.ratelimit;

import br.com.fiap.hackaton.auth.web.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

public class LoginRateLimitFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(LoginRateLimitFilter.class);
  private static final String KEY_PREFIX = "login-rate-limit:";

  private final Supplier<ProxyManager<String>> proxyManagerSupplier;
  private final ObjectMapper objectMapper;
  private final int capacity;
  private final int windowSeconds;

  public LoginRateLimitFilter(
      Supplier<ProxyManager<String>> proxyManagerSupplier,
      ObjectMapper objectMapper,
      int capacity,
      int windowSeconds) {
    this.proxyManagerSupplier = proxyManagerSupplier;
    this.objectMapper = objectMapper;
    this.capacity = capacity;
    this.windowSeconds = windowSeconds;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    RateLimitDecision decision = decide(request);

    if (decision.allowed()) {
      filterChain.doFilter(request, response);
      return;
    }

    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(decision.retryAfterSeconds()));
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response
        .getWriter()
        .write(
            objectMapper.writeValueAsString(
                new ErrorResponse("Too many login attempts. Try again later.")));
  }

  private RateLimitDecision decide(HttpServletRequest request) {
    try {
      ProxyManager<String> proxyManager = proxyManagerSupplier.get();
      String key = KEY_PREFIX + ClientIpResolver.resolve(request);
      Supplier<BucketConfiguration> configuration =
          () ->
              BucketConfiguration.builder()
                  .addLimit(Bandwidth.simple(capacity, Duration.ofSeconds(windowSeconds)))
                  .build();
      Bucket bucket = proxyManager.getProxy(key, configuration);
      ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

      if (probe.isConsumed()) {
        return RateLimitDecision.allow();
      }
      long retryAfterSeconds =
          Math.max(1, TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()));
      return RateLimitDecision.rejected(retryAfterSeconds);
    } catch (RuntimeException ex) {
      log.warn("Login rate limiter unavailable, allowing request without rate limiting", ex);
      return RateLimitDecision.allow();
    }
  }

  private record RateLimitDecision(boolean allowed, long retryAfterSeconds) {
    static RateLimitDecision allow() {
      return new RateLimitDecision(true, 0);
    }

    static RateLimitDecision rejected(long retryAfterSeconds) {
      return new RateLimitDecision(false, retryAfterSeconds);
    }
  }
}
