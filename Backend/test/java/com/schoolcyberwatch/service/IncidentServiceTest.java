package com.schoolcyberwatch.service;

import com.schoolcyberwatch.exception.GlobalExceptionHandler;
import com.schoolcyberwatch.exception.IncidentConflictException;
import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.repository.IncidentRepository;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IncidentServiceTest {

    private final IncidentRepository repository = mock(IncidentRepository.class);
    private final IncidentService service = new IncidentService(repository);

    @Test
    @DisplayName("Existing source alert is rejected before creating another incident")
    void rejectsAlreadyLinkedSourceAlert() {
        when(repository.existsBySourceAlertId("alert-existing")).thenReturn(true);

        assertThrows(IncidentConflictException.class,
                () -> service.create("title", "description", "High", "alert-existing", "computer"));
        verify(repository, never()).saveAndFlush(any(Incident.class));
    }

    @Test
    @DisplayName("Database uniqueness race becomes an incident conflict")
    void translatesUniqueConstraintRaceToConflict() {
        when(repository.existsBySourceAlertId("alert-race")).thenReturn(false, true);
        when(repository.saveAndFlush(any(Incident.class)))
                .thenThrow(new DataIntegrityViolationException("unique source alert id"));

        assertThrows(IncidentConflictException.class,
                () -> service.create("title", "description", "High", "alert-race", "computer"));
    }

    @Test
    @DisplayName("First incident for a source alert is created as OPEN")
    void createsFirstIncidentForSourceAlert() {
        when(repository.existsBySourceAlertId("alert-new")).thenReturn(false);
        when(repository.saveAndFlush(any(Incident.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var created = service.create("title", "description", "High", "alert-new", "computer");

        assertEquals(Incident.STATUS_OPEN, created.getStatus());
        assertEquals("alert-new", created.getSourceAlertId());
    }

    @Test
    @DisplayName("Incident source alert ID has a database unique constraint")
    void sourceAlertIdIsUniqueInDatabase() {
        Table table = Incident.class.getAnnotation(Table.class);
        boolean sourceAlertIdIsUnique = false;
        for (UniqueConstraint constraint : table.uniqueConstraints()) {
            if ("uk_incidents_source_alert_id".equals(constraint.name())) {
                sourceAlertIdIsUnique = true;
            }
        }
        assertTrue(sourceAlertIdIsUnique);
    }

    @Test
    @DisplayName("Incident duplicate error returns a safe HTTP 409 response")
    void conflictHandlerReturnsSafe409() {
        var response = new GlobalExceptionHandler().handleIncidentConflict(new IncidentConflictException());

        assertEquals(409, response.getStatusCode().value());
        assertEquals("An incident already exists for this security alert.", response.getBody().get("error"));
    }
}