package br.com.fiap.hackaton.auth.user;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @NotBlank(message = "email is required") String email,
    @NotBlank(message = "password is required") String password) {

  @Override
  public String toString() {
    return "LoginRequest[email=" + email + ", password=***]";
  }
}
