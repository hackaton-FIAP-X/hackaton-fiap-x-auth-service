package br.com.fiap.hackaton.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class FlywayRestartTest {

  @Container static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

  private Flyway flywayPointingAtContainer() {
    return Flyway.configure()
        .dataSource(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())
        .load();
  }

  @Test
  void restartingApplicationDoesNotReapplyOrBreakMigration() {
    MigrateResult firstBoot = flywayPointingAtContainer().migrate();
    assertThat(firstBoot.migrationsExecuted).isEqualTo(1);

    MigrateResult secondBoot = flywayPointingAtContainer().migrate();
    assertThat(secondBoot.migrationsExecuted).isEqualTo(0);

    assertThatCode(() -> flywayPointingAtContainer().validate()).doesNotThrowAnyException();
  }
}
