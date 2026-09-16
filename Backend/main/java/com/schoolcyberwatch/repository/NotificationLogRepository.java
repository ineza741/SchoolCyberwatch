package com.schoolcyberwatch.repository;

import com.schoolcyberwatch.model.NotificationLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationLogRepository extends JpaRepository<NotificationLog, Long> {
    boolean existsByAlertId(String alertId);
}
