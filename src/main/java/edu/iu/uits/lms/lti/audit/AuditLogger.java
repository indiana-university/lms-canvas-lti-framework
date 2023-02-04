package edu.iu.uits.lms.lti.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@Slf4j
public class AuditLogger {
    public final static String AUDIT_PREFACE = "[AUDIT LOG]";
    public AuditLogger() {
        log.info("AuditLogger Created");
    }
    @EventListener
    public void auditEventHandler(AuditApplicationEvent auditApplicationEvent) {
        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();

        log.info("{} Principal: {} - {}", AUDIT_PREFACE, auditEvent.getPrincipal(), auditEvent.getType());

        Map<String, Object> auditMap = auditEvent.getData();

        for (Map.Entry<String,Object> entry : auditMap.entrySet()) {
            log.info("{} Data: {} - {}", AUDIT_PREFACE, entry.getKey(), entry.getValue());
        }
    }
}
