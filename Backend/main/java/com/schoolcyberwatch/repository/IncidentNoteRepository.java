package com.schoolcyberwatch.repository;

import com.schoolcyberwatch.model.IncidentNote;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IncidentNoteRepository extends JpaRepository<IncidentNote, Long> {
}
