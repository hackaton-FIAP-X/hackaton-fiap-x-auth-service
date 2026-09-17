package br.com.fiap.hackaton.auth.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @Schema(description = "E-mail cadastrado do usuario", example = "maria.silva@example.com")
        @NotBlank(message = "email is required")
        String email,
    @Schema(description = "Senha em texto plano", example = "SenhaForte123")
        @NotBlank(message = "password is required")
        String password) {

  @Override
  public String toString() {
    return "LoginRequest[email=" + email + ", password=***]";
  }
}
