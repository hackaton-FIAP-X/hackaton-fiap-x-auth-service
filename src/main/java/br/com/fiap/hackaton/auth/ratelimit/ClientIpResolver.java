package br.com.fiap.hackaton.auth.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

final class ClientIpResolver {

  private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";

  private ClientIpResolver() {}

  static String resolve(HttpServletRequest request) {
    String forwardedFor = request.getHeader(FORWARDED_FOR_HEADER);
    if (forwardedFor != null && !forwardedFor.isBlank()) {
      return forwardedFor.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
