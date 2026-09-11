package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

class ProblemDetailAuthEntryPointTest {

  private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
  private final ProblemDetailAuthEntryPoint responder =
      new ProblemDetailAuthEntryPoint(objectMapper);

  @Test
  void commenceWritesA401ProblemDetail() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/videos");
    MockHttpServletResponse response = new MockHttpServletResponse();

    responder.commence(request, response, new BadCredentialsException("bad token"));

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
    JsonNode body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("status").asInt()).isEqualTo(401);
    assertThat(body.get("type").asText()).isEqualTo("urn:problem-type:unauthorized");
    assertThat(body.get("instance").asText()).isEqualTo("/videos");
  }

  @Test
  void handleWritesA403ProblemDetail() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/videos/1");
    MockHttpServletResponse response = new MockHttpServletResponse();

    responder.handle(request, response, new AccessDeniedException("nope"));

    assertThat(response.getStatus()).isEqualTo(403);
    JsonNode body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("status").asInt()).isEqualTo(403);
    assertThat(body.get("type").asText()).isEqualTo("urn:problem-type:forbidden");
  }
}
