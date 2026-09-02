package br.com.fiap.hackaton.auth.user;

public class EmailAlreadyRegisteredException extends RuntimeException {

  public EmailAlreadyRegisteredException(String email) {
    super("E-mail already registered: " + email);
  }
}
