package br.com.fiap.hackaton.auth;

import static org.assertj.core.api.Assertions.assertThat;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class FlywayMigrationTest {

  @Container
  @ServiceConnection
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired private Flyway flyway;
  @Autowired private DataSource dataSource;

  @Test
  void migrationAppliesCleanlyOnEmptyDatabase() {
    MigrationInfo current = flyway.info().current();

    assertThat(current).isNotNull();
    assertThat(current.getVersion().getVersion()).isEqualTo("1");
    assertThat(current.getState().isApplied()).isTrue();
  }

  @Test
  void usersTableHasExpectedColumns() {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

    var columns =
        jdbcTemplate.queryForList(
            "select column_name from information_schema.columns where table_name = 'users'",
            String.class);

    assertThat(columns)
        .containsExactlyInAnyOrder("id", "name", "email", "password_hash", "role", "created_at");
  }
}
