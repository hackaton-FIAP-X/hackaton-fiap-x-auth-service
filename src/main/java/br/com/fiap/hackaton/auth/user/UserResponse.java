package br.com.fiap.hackaton.auth.user;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(UUID id, String name, String email, UserRole role, Instant createdAt) {

  public static UserResponse from(User user) {
    return new UserResponse(
        user.getId(), user.getName(), user.getEmail(), user.getRole(), user.getCreatedAt());
  }
}
