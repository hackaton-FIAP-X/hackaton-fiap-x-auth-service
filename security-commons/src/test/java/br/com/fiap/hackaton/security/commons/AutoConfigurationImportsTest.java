package br.com.fiap.hackaton.security.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

class AutoConfigurationImportsTest {

  @Test
  void listsBothAutoConfigurationClasses() throws IOException {
    ClassPathResource resource =
        new ClassPathResource(
            "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports");

    String content;
    try (InputStream in = resource.getInputStream()) {
      content = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
    }

    List<String> lines = content.lines().map(String::trim).filter(line -> !line.isBlank()).toList();

    assertThat(lines)
        .containsExactlyInAnyOrder(
            ResourceServerAutoConfiguration.class.getName(),
            WebMvcAutoConfiguration.class.getName());
  }
}
