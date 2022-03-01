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

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import uk.ac.ox.ctl.lti13.lti.Claims;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OidcAuthenticationToken;

import java.util.Map;

import static edu.iu.uits.lms.lti.LTIConstants.CLAIMS_FAMILY_NAME_KEY;
import static edu.iu.uits.lms.lti.LTIConstants.CLAIMS_GIVEN_NAME_KEY;
import static edu.iu.uits.lms.lti.LTIConstants.CUSTOM_CANVAS_COURSE_ID_KEY;
import static edu.iu.uits.lms.lti.LTIConstants.CUSTOM_CANVAS_USER_ID_KEY;
import static edu.iu.uits.lms.lti.LTIConstants.CUSTOM_CANVAS_USER_LOGIN_ID_KEY;
import static edu.iu.uits.lms.lti.LTIConstants.CUSTOM_CANVAS_USER_SIS_ID_KEY;

public class OidcTokenUtils {

   public static String getCourseId(OidcAuthenticationToken token) {
      return getCustomValue(token, CUSTOM_CANVAS_COURSE_ID_KEY);
   }

   public static String getUserId(OidcAuthenticationToken token) {
      return getCustomValue(token, CUSTOM_CANVAS_USER_ID_KEY);
   }

   public static String getUserLoginId(OidcAuthenticationToken token) {
      return getCustomValue(token, CUSTOM_CANVAS_USER_LOGIN_ID_KEY);
   }

   public static String getSisUserId(OidcAuthenticationToken token) {
      return getCustomValue(token, CUSTOM_CANVAS_USER_SIS_ID_KEY);
   }

   public static String getPersonFamilyName(OidcAuthenticationToken token) {
      Map<String, Object> attrMap = getAttributes(token);
      String name = (String) attrMap.get(CLAIMS_FAMILY_NAME_KEY);
      return name;
   }

   public static String getPersonGivenName(OidcAuthenticationToken token) {
      Map<String, Object> attrMap = getAttributes(token);
      String name = (String) attrMap.get(CLAIMS_GIVEN_NAME_KEY);
      return name;
   }

   public static String[] getRoles(OidcAuthenticationToken token) {
      Map<String, Object> attrMap = getAttributes(token);
      JSONArray jsonObj = (JSONArray) attrMap.get(Claims.ROLES);
      return jsonObj.toArray(String[]::new);
   }

   public static String getCustomValue(OidcAuthenticationToken token, String key) {
      Map<String, Object> attrMap = getAttributes(token);
      JSONObject jsonObj = (JSONObject) attrMap.get(Claims.CUSTOM);
      return jsonObj.getAsString(key);
   }

   private static Map<String, Object> getAttributes(OidcAuthenticationToken token) {
      return token.getPrincipal().getAttributes();
   }
}