# School CyberWatch

A security monitoring, incident detection, and alert platform for secondary
schools in Rwanda, built on top of Wazuh.

Flow: Windows school computers -> Wazuh agents -> Wazuh manager (192.168.56.101)
-> Spring Boot backend -> React dashboard.

## Technology

- Frontend: React + Vite (port 5173)
- Backend: Java 17+ / Spring Boot 3.2 (port 8080)
- Database: MySQL 8 (database `School_Cyber_Watch`)
- Security monitoring: Wazuh 4.x - manager API (port 55000, agents) +
  indexer/OpenSearch (port 9200, alerts)
- Email: SMTP (e.g. Gmail App Password) - optional, env-configured
- PDF: OpenPDF

## Monitored detections

| Rule  | Event                    | Dashboard severity |
|-------|--------------------------|--------------------|
| 60122 | Windows failed login     | Medium             |
| 100200| Brute-force attack       | Critical (+ email) |
| 550   | Protected file modified  | High               |
| 553   | Protected file deleted   | High               |

## Run the backend

```bash
cd Backend
export JAVA_HOME="/c/Program Files/Java/jdk-21.0.12"   # adjust as needed
set -a; source env.properties; set +a                   # DB/JWT/Wazuh/mail settings
../tools/apache-maven-3.9.9/bin/mvn spring-boot:run
```

First start creates the tables and a default ICT administrator
(`ADMIN_EMAIL` / `ADMIN_PASSWORD` in env.properties, default
`admin@school.edu.rw` / `Admin@123`).

## Run the frontend

```bash
cd Frontend
npm install
npm run dev          # http://localhost:5173
```

`Frontend/.env` (copy from `.env.example`) sets `VITE_API_BASE_URL`,
default `http://localhost:8080/api`.

## Wazuh credentials

Set `WAZUH_API_PASSWORD` (manager API, agent list) and `WAZUH_INDEXER_PASSWORD`
(indexer, alert data) in `Backend/env.properties`. When Wazuh is offline the
API answers 503 with
"Security monitoring service temporarily unavailable." and the dashboard
shows the same message - no fake data, no crash.

## Email alerts

Set in `Backend/env.properties`:

```
MAIL_ENABLED=true
MAIL_USERNAME=your.address@gmail.com
MAIL_PASSWORD=your-16-char-app-password
ALERT_RECIPIENT=ict.admin@school.edu.rw
```

High/critical alerts trigger one email per alert (deduplicated in the
`notifications` table). Test from Reports -> "Send test email".

## Project layout

```
Backend/main/java/com/schoolcyberwatch/
  config/      Security (JWT), CORS, Wazuh properties, bootstrap admin
  controller/  auth, dashboard, endpoints, alerts, incidents, reports
  dto/         SecurityEvent, EndpointInfo, IncidentDto, auth DTOs
  model/       User, Incident, IncidentNote, NotificationLog (JPA)
  repository/  Spring Data repositories
  security/    JwtService, JwtAuthenticationFilter, UserDetailsService
  service/     WazuhClient (manager), WazuhIndexerClient (alerts),
               WazuhService, SecurityEventMapper,
               IncidentService, NotificationService, ReportService
Frontend/src/
  components/  AppShell (sidebar), BrandMark
  config/      API base URL
  pages/       Landing, Login, Dashboard, Computers, Alerts,
               Incidents, Reports
  services/    auth.js (token), api.js (central request layer)
```
