# School CyberWatch frontend

Frontend for a security monitoring, incident detection, and alert platform for secondary schools in Rwanda.

## Phase 1

This phase provides the React application setup, responsive application shell, sidebar navigation, page placeholders, and centralized API configuration. It does not connect to Wazuh or a backend and does not contain mock security records.

## Folder structure

```text
src/
  components/     Reusable layout components
  config/         Environment and API configuration
  pages/          Route-level page components
  services/       Future backend request functions
  styles/         Global styling and design tokens
```

## Install and run

```powershell
npm install
npm run dev
```

Open the local address printed by Vite, usually `http://localhost:5173`.

## Planned frontend structure

- Login: authorized ICT staff sign-in
- Dashboard: plain-language security overview
- Computers: monitored endpoints
- Security alerts: filtering and alert details
- Incidents: incident workflow and notes
- Reports: report generation request

`src/config/api.js` is the single place to set the backend URL. Future service functions belong in `src/services`, keeping backend URLs out of components.
