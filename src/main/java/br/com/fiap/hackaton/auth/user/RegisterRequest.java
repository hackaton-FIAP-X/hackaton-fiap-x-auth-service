package br.com.fiap.hackaton.auth.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank(message = "name is required") String name,
    @NotBlank(message = "email is required")
        @Email(message = "email must be a valid email address")
        String email,
    @NotBlank(message = "password is required")
        @Size(min = 8, message = "password must be at least 8 characters")
        String password) {

  @Override
  public String toString() {
    return "RegisterRequest[name=" + name + ", email=" + email + ", password=***]";
  }
}
