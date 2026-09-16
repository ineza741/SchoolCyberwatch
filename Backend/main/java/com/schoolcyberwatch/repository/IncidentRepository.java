package com.schoolcyberwatch.repository;

import com.schoolcyberwatch.model.Incident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    /** Newest first for the incidents page. */
    List<Incident> findAllByOrderByCreatedAtDesc();

    long countByStatus(String status);

    List<Incident> findByStatusOrderByCreatedAtDesc(String status);
}
