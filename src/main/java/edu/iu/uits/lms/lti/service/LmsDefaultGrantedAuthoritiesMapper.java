package edu.iu.uits.lms.lti.service;

/*-
 * #%L
 * LMS Canvas LTI Framework Services
 * %%
 * Copyright (C) 2015 - 2022 Indiana University
 * %%
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Indiana University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */

import com.nimbusds.jose.shaded.json.JSONObject;
import edu.iu.uits.lms.lti.LTIConstants;
import edu.iu.uits.lms.lti.repository.DefaultInstructorRoleRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.actuate.security.AuthenticationAuditListener;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class LmsDefaultGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

   private DefaultInstructorRoleRepository defaultInstructorRoleRepository;

   private ApplicationEventPublisher applicationEventPublisher;

   public LmsDefaultGrantedAuthoritiesMapper() {}

   public LmsDefaultGrantedAuthoritiesMapper(DefaultInstructorRoleRepository defaultInstructorRoleRepository,
                                             ApplicationEventPublisher applicationEventPublisher) {
      this.defaultInstructorRoleRepository = defaultInstructorRoleRepository;
      this.applicationEventPublisher = applicationEventPublisher;
   }

   @Override
   public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
      List<GrantedAuthority> remappedAuthorities = new ArrayList<>();
      remappedAuthorities.addAll(authorities);
      for (GrantedAuthority authority: authorities) {
         OidcUserAuthority userAuth = (OidcUserAuthority) authority;
         OidcTokenUtils oidcTokenUtils = new OidcTokenUtils(userAuth.getAttributes());
         log.debug("LTI Claims: {}", userAuth.getAttributes());
         String[] roles = oidcTokenUtils.getCustomInstructureMembershipRoles();
         String newAuthString = returnEquivalentAuthority(roles, getDefaultInstructorRoles());
         OidcUserAuthority newUserAuth = new OidcUserAuthority(newAuthString, userAuth.getIdToken(), userAuth.getUserInfo());

         remappedAuthorities.add(newUserAuth);

         try {
            JSONObject jsonObject = (JSONObject) userAuth.getAttributes()
                    .get("https://purl.imsglobal.org/spec/lti/claim/custom");

            String userId   = jsonObject.getAsString("canvas_user_login_id");
            String courseId = jsonObject.getAsString("canvas_course_id");

            Map<String, Object> details = new HashMap<>();

            details.put("USER ID", userId);
            details.put("COURSE ID", courseId);

            AuditApplicationEvent auditApplicationEvent = new AuditApplicationEvent("LTI",
                    AuthenticationAuditListener.AUTHENTICATION_SUCCESS.toString(),
                    details
            );

            applicationEventPublisher.publishEvent(auditApplicationEvent);
         } catch (Exception e) {
            log.error(e.getMessage());
         }
      }

      return remappedAuthorities;
   }


   /**
    * Given a list of user roles, return the internal equivalent role
    * Can be overridden by an implementing class if the role needs are different.
    * @param userRoles List of user roles coming from the lti launch
    * @param instructorRoles List of roles deemed as "Instructor" equivalents
    * @return Return the appropriate authority
    */
   protected String returnEquivalentAuthority(String[] userRoles, List<String> instructorRoles) {
      for (String instructorRole : instructorRoles) {
         if (Arrays.asList(userRoles).contains(instructorRole)) {
            return LTIConstants.INSTRUCTOR_AUTHORITY;
         }
      }
      return LTIConstants.STUDENT_AUTHORITY;
   }

   protected List<String> getDefaultInstructorRoles() {
      List<String> allInstructorRoles = defaultInstructorRoleRepository.findInstructorRoles();
      return allInstructorRoles;
   }
}
