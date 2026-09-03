package br.com.fiap.hackaton.auth.web;

import java.util.List;

public record ValidationErrorResponse(String message, List<FieldErrorDetail> errors) {

  public record FieldErrorDetail(String field, String message) {}
}
