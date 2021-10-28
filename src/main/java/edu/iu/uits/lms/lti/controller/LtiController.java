package edu.iu.uits.lms.lti.controller;

/*-
 * #%L
 * LMS Canvas LTI Framework Services
 * %%
 * Copyright (C) 2015 - 2021 Indiana University
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

import edu.iu.uits.lms.lti.LTIConstants;
import edu.iu.uits.lms.lti.model.LmsLtiAuthz;
import edu.iu.uits.lms.lti.service.LtiAuthorizationServiceImpl;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthValidator;
import net.oauth.SimpleOAuthValidator;
import net.oauth.server.OAuthServlet;
import net.oauth.signature.OAuthSignatureMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.tsugi.basiclti.BasicLTIConstants;
import org.tsugi.basiclti.BasicLTIUtil;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by chmaurer on 12/19/14.
 */
@Controller
@Slf4j
public abstract class LtiController {
    private static final long serialVersionUID = -5793392467087229614L;
    private static final String OAUTH_MESSAGE = "oauth_message";

    protected static final String CUSTOM_CANVAS_COURSE_ID = "custom_canvas_course_id";
    protected static final String CUSTOM_CANVAS_USER_ID = "custom_canvas_user_id";
    protected static final String CUSTOM_CANVAS_USER_LOGIN_ID = "custom_canvas_user_login_id";
    protected static final String CUSTOM_OPEN_IN_NEW_WINDOW = "custom_open_in_new_window";

    public enum LAUNCH_MODE {
        /**
         * Default implementation.  Will just be to do a response.redirect to the launch url.
         */
        NORMAL,

        /**
         * The dispatcher will forward the request on to the launch url.
         */
        FORWARD,

        /**
         * Should the LTI tool be opened in Proxy mode?
         * Intended to be overridden by an implementing class.
         */
        PROXY,

        /**
         * Should the LTI tool be opened in a new window?
         */
        WINDOW
    }

    @Autowired
    private LtiAuthorizationServiceImpl ltiAuthorizationService;

    /**
     * launch url will be supplied by the implementing servlet
     * @param paramMap Map of parameters that the implementing servlet will need to build the launch url
     * @return The final launch url
     */
    protected abstract String getLaunchUrl(Map<String, String> paramMap);

    /**
     * Get the necessary parameters to pass along to the launch
     * @param payload Map of request parameters
     * @param claims Claims from the jwt token (lti 1.3)
     * @return Map of parameters that are needed by the launch
     */
    protected abstract Map<String, String> getParametersForLaunch(Map<String, String> payload, Claims claims);

    /**
     * Get the context around this particular tool
     * @return The string representation of the tool context.
     */
    protected abstract String getToolContext();

    @RequestMapping(method = RequestMethod.POST)
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        log.debug("begin doPost()");

        // There is a problem with special characters and Canvas if the encoding is not set, so this gets around the issue
        String encoding = request.getCharacterEncoding();
        if (encoding == null) {
            try {
                request.setCharacterEncoding("UTF-8");
            } catch (UnsupportedEncodingException uee) {
                throw new UnsupportedEncodingException("The request did not have an encoding and was unable to be set to UTF-8");
            }
        }

        Map<String, Object> payload = new HashMap<String, Object>();
        payload.put(OAUTH_MESSAGE, OAuthServlet.getMessage(request, null));
        Map<String, String> payloadStr = extractPayloadFromRequest(request);
        payload.putAll(payloadStr);

        Claims claims = null;
        try {
            claims = validateAndAuthorize(payload);
        } catch (LTIException e) {
            log.error("validation error", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getLocalizedMessage());
            return;
        }

        Map<String, String> launchParams = getParametersForLaunch(payloadStr, claims);
        String launchUrl = getLaunchUrl(launchParams);
        log.debug("Attempting to redirect to " + launchUrl);

        preLaunchSetup(launchParams, request, response);
        switch (launchMode()) {
            case WINDOW:
                response.setContentType("text/html");
                PrintWriter out = response.getWriter();

                out.println("<html>");
                out.println("<head>");
                out.println("<title>Redirect</title>");
                out.println("</head>");
                out.println("<body>");
                out.println("<script>window.open('" + launchUrl + "', '_blank');</script>");
                out.println("</body>");
                out.println("</html>");
                break;
            case PROXY:
                //noop
                break;
            case FORWARD:
                RequestDispatcher dispatcher = request.getRequestDispatcher(launchUrl);
                dispatcher.forward(request, response);
                break;
            default:
                response.sendRedirect(launchUrl);
                break;

        }
    }

    /**
     * How will the launch url be executed?
     * Intended to be overridden by an implementing class.
     * @return Launch mode
     */
    protected LAUNCH_MODE launchMode() {
        return LAUNCH_MODE.NORMAL;
    }

    /**
     * Run any steps necessary to occur before the launch of the tool
     * Intended to be overridden by an implementing class.
     * @param launchParams Map of launch parameters
     * @param request HttpServletRequest
     * @param response  HttpServletResponse
     */
    protected void preLaunchSetup(Map<String, String> launchParams, HttpServletRequest request, HttpServletResponse response) {

    }

    /**
     * Extract the parameters from the request and dump them into a map
     * @param request HttpServletRequest
     * @return Map of request parameters
     */
    private Map<String, String> extractPayloadFromRequest(HttpServletRequest request) {
        Map<String, String> payload = new HashMap<String, String>();

        for (Enumeration<String> e = request.getParameterNames(); e.hasMoreElements(); ) {
            String key = e.nextElement();
            String value = request.getParameter(key);
            payload.put(key, value);

            log.debug("key: " + key + "(" + value + ")");
        }

        return payload;
    }

    /**
     * Ensure that this is a proper lti request and it is authorized
     * @param payload Map of the request parameters
     * @return Claims from the jwt token (lti 1.3)
     * @throws LTIException Exceptions for various launch problems
     */
    protected Claims validateAndAuthorize(Map<String, Object> payload) throws LTIException {
        //check parameters
        String ltiMessageType = (String) payload.get(BasicLTIConstants.LTI_MESSAGE_TYPE);
        String ltiVersion = (String) payload.get(BasicLTIConstants.LTI_VERSION);
        String oauthConsumerKey = (String) payload.get("oauth_consumer_key");
        String userId = (String) payload.get(BasicLTIConstants.USER_ID);
        String contextId = (String) payload.get(BasicLTIConstants.CONTEXT_ID);

        log.debug("validate()");
        if(!BasicLTIUtil.equals(ltiMessageType, "basic-lti-launch-request")) {
            throw new LTIException("launch.invalid", "lti_message_type="+ltiMessageType, null);
        }
        if(!BasicLTIUtil.equals(ltiVersion, "LTI-1p0")) {
            throw new LTIException( "launch.invalid", "lti_version="+ltiVersion, null);
        }
        if(BasicLTIUtil.isBlank(oauthConsumerKey)) {
            throw new LTIException( "launch.missing", "oauth_consumer_key", null);
        }
        if(BasicLTIUtil.isBlank(userId)) {
            throw new LTIException( "launch.missing", "user_id", null);
        }
        log.debug("user_id=" + userId);

        // Lookup the secret
        final LmsLtiAuthz ltiAuthz = ltiAuthorizationService.findByKeyContextActive(oauthConsumerKey, getToolContext());

        if (ltiAuthz == null || ltiAuthz.getSecret() == null) {
            throw new LTIException( "launch.key.notfound",oauthConsumerKey, null);
        }
        final OAuthMessage oam = (OAuthMessage) payload.get(OAUTH_MESSAGE);
        final OAuthValidator oav = new SimpleOAuthValidator();
        final OAuthConsumer cons = new OAuthConsumer("about:blank#OAuth+CallBack+NotUsed", oauthConsumerKey,ltiAuthz.getSecret(), null);
        final OAuthAccessor acc = new OAuthAccessor(cons);
        String baseString = null;
        try {
            baseString = OAuthSignatureMethod.getBaseString(oam);
        } catch (Exception e) {
            log.error("ERROR: " + e.getLocalizedMessage() + e);
        }
        log.debug("BaseString: " + baseString);
        try {
            oav.validateMessage(oam, acc);
        } catch (OAuthException e) {
            throw new LTIException( "launch.no.validate", e.getLocalizedMessage(), e.getCause());
        } catch (IOException | URISyntaxException e) {
            throw new LTIException( "launch.no.validate", contextId, e);
        }
        return null;
    }

    /**
     * Given a list of user roles, return the internal equivalent role
     * Can be overridden by an implementing class if the role needs are different.
     * @param userRoles List of user roles coming from the lti launch
     * @param instructorRoles List of roles deemed as "Instructor" equivalents
     * @return Return the appropriate authority
     */
    protected String returnEquivalentAuthority(List<String> userRoles, List<String> instructorRoles) {
        for (String instructorRole : instructorRoles) {
            if (userRoles.contains(instructorRole)) {
                return LTIConstants.INSTRUCTOR_AUTHORITY;
            }
        }
        return LTIConstants.STUDENT_AUTHORITY;
    }

    protected List<String> getDefaultInstructorRoles() {
        return Arrays.asList("Instructor", "urn:lti:instrole:ims/lis/Administrator", "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor");
    }


}
