package br.com.fiap.hackaton.auth.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @Schema(description = "Nome completo do usuario", example = "Maria Silva")
        @NotBlank(message = "name is required")
        String name,
    @Schema(description = "E-mail unico usado como login", example = "maria.silva@example.com")
        @NotBlank(message = "email is required")
        @Email(message = "email must be a valid email address")
        String email,
    @Schema(
            description = "Senha em texto plano, entre 8 e 128 caracteres",
            example = "SenhaForte123")
        @NotBlank(message = "password is required")
        @Size(min = 8, max = 128, message = "password must be between 8 and 128 characters")
        String password) {

  @Override
  public String toString() {
    return "RegisterRequest[name=" + name + ", email=" + email + ", password=***]";
  }
}
