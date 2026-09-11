package br.com.fiap.hackaton.security.commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

public class ProblemDetailAuthEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {

  public static final URI UNAUTHORIZED_TYPE = URI.create("urn:problem-type:unauthorized");
  public static final URI FORBIDDEN_TYPE = URI.create("urn:problem-type:forbidden");

  private final ObjectMapper objectMapper;

  public ProblemDetailAuthEntryPoint(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void commence(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException {
    write(
        request,
        response,
        HttpStatus.UNAUTHORIZED,
        UNAUTHORIZED_TYPE,
        "Unauthorized",
        "Missing, expired or invalid token.");
  }

  @Override
  public void handle(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
      throws IOException {
    write(
        request,
        response,
        HttpStatus.FORBIDDEN,
        FORBIDDEN_TYPE,
        "Forbidden",
        "The token does not allow this operation.");
  }

  private void write(
      HttpServletRequest request,
      HttpServletResponse response,
      HttpStatus status,
      URI type,
      String title,
      String detail)
      throws IOException {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    problem.setType(type);
    problem.setTitle(title);
    problem.setInstance(URI.create(request.getRequestURI()));
    problem.setProperty("timestamp", Instant.now());

    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    objectMapper.writeValue(response.getWriter(), problem);
  }
}
