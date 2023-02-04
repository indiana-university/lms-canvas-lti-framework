package edu.iu.uits.lms.lti.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.actuate.security.AuthenticationAuditListener;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.HashMap;

@Slf4j
public class AuditableRestSpringObject {
    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    @ModelAttribute
    public void auditPublish() {
        AuditApplicationEvent auditApplicationEvent = new AuditApplicationEvent("REST",
                AuthenticationAuditListener.AUTHENTICATION_SUCCESS.toString(),
                new HashMap<>()
        );

        applicationEventPublisher.publishEvent(auditApplicationEvent);
    }
}