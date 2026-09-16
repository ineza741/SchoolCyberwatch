package com.schoolcyberwatch.service;

import com.lowagie.text.Document;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.repository.IncidentRepository;
import com.schoolcyberwatch.exception.WazuhUnavailableException;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Builds the PDF security report:
 * title, reporting period, monitored computers, alert totals per type,
 * severity breakdown, incident counts and basic recommendations.
 * Alert data comes live from Wazuh; incident data from the database.
 */
@Service
public class ReportService {

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("d MMM uuuu").withZone(ZoneId.systemDefault());

    private final WazuhService wazuhService;
    private final IncidentRepository incidentRepository;

    public ReportService(WazuhService wazuhService, IncidentRepository incidentRepository) {
        this.wazuhService = wazuhService;
        this.incidentRepository = incidentRepository;
    }

    /** Generates the PDF; daysBack defines the reporting period (default 30). */
    public byte[] generateSecurityReport(int daysBack) {
        Instant since = Instant.now().minus(Duration.ofDays(Math.max(daysBack, 1)));
        String sinceIso = since.toString();

        // These calls throw WazuhUnavailableException (handled globally) when
        // the monitoring service is offline - the report needs live data.
        long computers = wazuhService.countAgents();
        long failedLogins = wazuhService.countAlerts("60122", sinceIso);
        long bruteForce = wazuhService.countAlerts("100200", sinceIso);
        long fileModified = wazuhService.countAlerts("550", sinceIso);
        long fileDeleted = wazuhService.countAlerts("553", sinceIso);

        long open = incidentRepository.countByStatus(Incident.STATUS_OPEN);
        long investigating = incidentRepository.countByStatus(Incident.STATUS_INVESTIGATING);
        long resolved = incidentRepository.countByStatus(Incident.STATUS_RESOLVED);

        try (ByteArrayOutputStream pdf = new ByteArrayOutputStream()) {
            Document document = new Document(PageSize.A4, 50, 50, 55, 45);
            PdfWriter.getInstance(document, pdf);
            document.open();

            Font title = new Font(Font.HELVETICA, 20, Font.BOLD);
            Font heading = new Font(Font.HELVETICA, 13, Font.BOLD);
            Font normal = new Font(Font.HELVETICA, 10);
            Font small = new Font(Font.HELVETICA, 9);

            document.add(new Paragraph("School CyberWatch - Security Report", title));
            Paragraph period = new Paragraph(
                    "Reporting period: " + DATE_FORMAT.format(since) + " to " + DATE_FORMAT.format(Instant.now()),
                    normal);
            period.setSpacingBefore(6);
            document.add(period);
            document.add(new Paragraph("Generated: " + DATE_FORMAT.format(Instant.now()), small));

            document.add(spacer());
            document.add(new Paragraph("1. Monitoring overview", heading));
            document.add(new Paragraph("Monitored computers (Wazuh agents): " + computers, normal));

            document.add(spacer());
            document.add(new Paragraph("2. Security alerts (period)", heading));
            PdfPTable alertTable = new PdfPTable(2);
            alertTable.setWidthPercentage(70);
            alertTable.addCell(cell("Alert type"));
            alertTable.addCell(cell("Count"));
            alertTable.addCell(cell("Failed logins (rule 60122)"));
            alertTable.addCell(cell(String.valueOf(failedLogins)));
            alertTable.addCell(cell("Brute-force attacks (rule 100200)"));
            alertTable.addCell(cell(String.valueOf(bruteForce)));
            alertTable.addCell(cell("Protected files modified (rule 550)"));
            alertTable.addCell(cell(String.valueOf(fileModified)));
            alertTable.addCell(cell("Protected files deleted (rule 553)"));
            alertTable.addCell(cell(String.valueOf(fileDeleted)));
            long total = failedLogins + bruteForce + fileModified + fileDeleted;
            alertTable.addCell(cell("Total security alerts"));
            alertTable.addCell(cell(String.valueOf(total)));
            document.add(alertTable);

            document.add(spacer());
            document.add(new Paragraph("3. Severity breakdown", heading));
            document.add(new Paragraph(
                    "Critical (brute force): " + bruteForce
                            + "   |   High (file integrity): " + (fileModified + fileDeleted)
                            + "   |   Medium (failed logins): " + failedLogins,
                    normal));

            document.add(spacer());
            document.add(new Paragraph("4. Incident management", heading));
            document.add(new Paragraph(
                    "Open incidents: " + open
                            + "   |   Investigating: " + investigating
                            + "   |   Resolved: " + resolved,
                    normal));

            document.add(spacer());
            document.add(new Paragraph("5. Security recommendations", heading));
            document.add(new Paragraph(
                    "- Review accounts with repeated failed logins and enforce strong passwords.\n"
                            + "- Keep automatic screen lock enabled on all school computers.\n"
                            + "- Restrict write access to the protected examinations folder.\n"
                            + "- Ensure every new school computer gets a Wazuh agent installed.\n"
                            + "- Open and resolve incidents promptly; document actions taken.",
                    normal));

            document.close();
            return pdf.toByteArray();
        } catch (WazuhUnavailableException e) {
            throw e; // handled by GlobalExceptionHandler -> 503
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate the PDF report: " + e.getMessage(), e);
        }
    }

    private static com.lowagie.text.Element spacer() {
        Paragraph p = new Paragraph(" ");
        p.setSpacingBefore(8);
        return p;
    }

    private static com.lowagie.text.pdf.PdfPCell cell(String text) {
        return new com.lowagie.text.pdf.PdfPCell(new Paragraph(text,
                new Font(Font.HELVETICA, 10)));
    }
}
