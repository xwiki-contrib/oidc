/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.oidc.auth.internal;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.script.ScriptContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.servlet.HttpServletUtils;
import org.xwiki.container.servlet.filters.SavedRequestManager;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.properties.ConverterManager;
import org.xwiki.script.ScriptContextManager;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthenticator;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Authenticate user trough an OpenID Connect provider.
 * 
 * @version $Id$
 * @since 1.35.0
 */
@Component
@Singleton
@Named(OIDCAuthService.ID)
public class OIDCAuthService extends XWikiAuthServiceImpl implements XWikiAuthServiceComponent
{
    /**
     * The identifier of the authenticator.
     */
    public static final String ID = "oidc";

    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCAuthService.class);

    private static final String OIDC_SRID = "oidc.srid";

    private static final Set<String> LOGIN_ACTIONS_EXCLUSIVE = new HashSet<>(Arrays.asList("login", "loginsubmit"));

    /**
     * When local authentication is enabled, we cannot intercept loginsubmit as it's the action called by the login for.
     */
    private static final Set<String> LOGIN_ACTIONS_TRYLOCAL = new HashSet<>(Arrays.asList("login"));

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCManager manager;

    @Inject
    private ConverterManager converter;

    @Inject
    private OIDCUserManager users;

    @Inject
    private ScriptContextManager scriptContextManager;

    @Inject
    private OIDCSilentReauthentication silentReauthentication;

    private final Map<XWikiAuthenticator, OIDCAuthenticator> oidcAuthenticators = new ConcurrentHashMap<>();

    @Override
    public String getId()
    {
        return ID;
    }

    @Override
    protected XWikiAuthenticator getAuthenticator(XWikiContext context) throws XWikiException
    {
        XWikiAuthenticator standard = super.getAuthenticator(context);

        if (this.configuration.isTryLocalEnabled()) {
            return standard;
        }

        // If local authentication is disabled, return an authenticator without any support for standard cookies or
        // basic auth, but which still rely on the standard authenticator (initialized for the current wiki) for the
        // rest (logout detection, login page, etc.)
        return this.oidcAuthenticators.computeIfAbsent(standard, OIDCAuthenticator::new);
    }

    private Set<String> getLoginActions()
    {
        return this.configuration.isTryLocalEnabled() ? LOGIN_ACTIONS_TRYLOCAL : LOGIN_ACTIONS_EXCLUSIVE;
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        LOGGER.debug("Checking if there is already a user in the session");

        // Check if there is already a user in the session, take care of logout, etc.
        XWikiUser user = super.checkAuth(context);

        if (user == null) {
            LOGGER.debug("No user could be found in the session, starting an OpenID Connect authentication");

            // Try OIDC if there is no already authenticated user
            try {
                checkAuthOIDC(context);
            } catch (Exception e) {
                throw new XWikiException("Failed OIDC authentication", e);
            }
        } else {
            // See if we need to refresh the user information
            LOGGER.debug("Checking if a user info refresh is needed");

            this.users.checkUpdateUserInfo();
        }

        return user;
    }

    private void checkAuthOIDC(XWikiContext context) throws Exception
    {
        // Check if OIDC is skipped or not and remember it
        boolean isSkipped = this.configuration.isSkipped();
        this.configuration.setSessionAttribute(OIDCClientConfiguration.PROP_SKIPPED, isSkipped);
        if (isSkipped) {
            return;
        }

        // Check if the current session already have associated logged in OIDC metadata
        boolean loggedOut = false;
        if (this.configuration.getAccessToken() != null) {
            // Make sure the session is free from anything related to a previously authenticated user (i.e. in case we
            // are just after a logout)
            this.users.logout();
            loggedOut = true;
        }

        // If the URL contain a OIDC provider, assume it was asked to the user
        String provider = context.getRequest().getParameter(OIDCClientConfiguration.PROP_PROVIDER);
        if (provider != null) {
            authenticate(context);

            return;
        }

        // Ugly but there is no other way for a custom authenticator to be called when someone explicitly request to
        // login...
        if (getLoginActions().contains(context.getAction())) {
            showLoginOIDC(context);

            return;
        }

        // A user who just logged out must not be authenticated again right away
        if (!loggedOut && this.silentReauthentication.startAttempt()) {
            startSilentAuthentication(context);
        }
    }

    /**
     * Restart the authentication of a user coming back after the session expired, asking the provider not to interact
     * with the user: the provider sends the user right back, authenticated if its own session is still alive.
     */
    private void startSilentAuthentication(XWikiContext context)
    {
        try {
            // The provider cannot be chosen by the user without interaction
            if (this.configuration.getAuthorizationOIDCEndpoint() != null) {
                LOGGER.debug("Starting a silent OpenID Connect re-authentication");

                authenticate(handleSavedRequest(context), context, new Prompt(Prompt.Type.NONE));
            }
        } catch (Exception e) {
            // The user just stays unauthenticated, as without silent re-authentication
            LOGGER.warn("Failed to start the silent OpenID Connect re-authentication: {}",
                ExceptionUtils.getRootCauseMessage(e));
        }
    }

    private void showLoginOIDC(XWikiContext context) throws Exception
    {
        // Check endpoints
        Endpoint endpoint = this.configuration.getAuthorizationOIDCEndpoint();

        // Save the request to not loose sent content
        String savedRequestId = handleSavedRequest(context);

        // If no endpoint can be found, ask for it
        if (endpoint == null) {
            // Give the srid to the template to remember it
            this.scriptContextManager.getCurrentScriptContext().setAttribute("srid", savedRequestId,
                ScriptContext.GLOBAL_SCOPE);

            this.manager.executeTemplate("oidc/client/provider.vm", context.getResponse());

            context.setFinished(true);

            return;
        }

        authenticate(savedRequestId, context, null);
    }

    private String getSavedRequestIdentifier(XWikiRequest request)
    {
        String savedRequestId = request.getParameter(SavedRequestManager.getSavedRequestIdentifier());
        if (savedRequestId == null) {
            savedRequestId = request.getParameter(OIDC_SRID);
        }

        return savedRequestId;
    }

    private String handleSavedRequest(XWikiContext xcontext)
    {
        XWikiRequest request = xcontext.getRequest();
        String savedRequestId = getSavedRequestIdentifier(request);
        if (StringUtils.isEmpty(savedRequestId)) {
            // Save the request to not loose sent content
            savedRequestId = SavedRequestManager.saveRequest(request);
        }

        return savedRequestId;
    }

    private void authenticate(XWikiContext context) throws URISyntaxException, IOException, GeneralException
    {
        // Save the request to not loose sent content
        String savedRequestId = handleSavedRequest(context);

        authenticate(savedRequestId, context, null);
    }

    private String createSuccessRedirectURI(String savedRequestId, XWikiContext context)
        throws UnsupportedEncodingException
    {
        String redirectBack = HttpServletUtils.getSourceURL(context.getRequest()).toExternalForm();

        // Append the SRID to the redirect URL
        if (StringUtils.isNotBlank(savedRequestId)) {
            StringBuilder builder = new StringBuilder(redirectBack);
            if (redirectBack.indexOf('?') != -1) {
                builder.append('&');
            } else {
                builder.append('?');
            }
            builder.append(SavedRequestManager.getSavedRequestIdentifier());
            builder.append('=');
            builder.append(URLEncoder.encode(savedRequestId, "UTF8"));

            redirectBack = builder.toString();
        }

        return redirectBack;
    }

    private void authenticate(String savedRequestId, XWikiContext context, Prompt prompt)
        throws URISyntaxException, IOException, GeneralException
    {
        // Make sure the session is not modified by a callback or another authorization start (from other browser tabs,
        // for example) while this authentication is started
        Lock lock = this.configuration.getSessionLock();
        lock.lock();
        try {
            startAuthentication(savedRequestId, context, prompt);
        } finally {
            lock.unlock();
        }
    }

    private void startAuthentication(String savedRequestId, XWikiContext context, Prompt prompt)
        throws URISyntaxException, IOException, GeneralException
    {
        // Generate callback URL
        URI callback = this.manager.createEndPointURI(CallbackOIDCEndpoint.HINT);

        // Remember various stuff in the session so that callback can access it
        XWikiRequest request = context.getRequest();

        // Clear previous OIDC session information
        this.configuration.resetOIDCSession();

        // Get configured response type
        ResponseType responseType = this.configuration.getResponseType();

        // Generate unique state
        State state = new State();
        this.configuration.setSessionState(state.getValue());

        // Remember the initial request URL
        this.configuration.setSuccessRedirectURI(URI.create(createSuccessRedirectURI(savedRequestId, context)));

        // Remember the provider when it's provided by the request (which is only allowed when it's not configured
        // already). Unless the authorization endpoint is configured, in which case the provider is not needed and
        // should not be provided by the user.
        if (this.configuration.getProvider() == null && this.configuration.getAuthorizationOIDCEndpoint() == null) {
            maybeStoreRequestParameterInSession(request, OIDCClientConfiguration.PROP_PROVIDER);
        }

        // The authorization endpoint might still be unknown, when the provider was just indicated by the request but
        // its metadata does not contain any authorization endpoint
        Endpoint authorizationEndpoint = this.configuration.getAuthorizationOIDCEndpoint();
        if (authorizationEndpoint == null) {
            throw new GeneralException("No authorization endpoint could be found for the configured provider");
        }

        // Create the request URL
        AuthenticationRequest.Builder requestBuilder = new AuthenticationRequest.Builder(responseType,
            this.configuration.getScope(), this.configuration.getClientID(), callback);
        requestBuilder.endpointURI(authorizationEndpoint.getURI());

        // Nonce, if required
        Nonce nonce;
        if (Nonce.isRequired(responseType)) {
            nonce = new Nonce();

            // Set the nonce in the request
            requestBuilder.nonce(nonce);

            // Store the nonce in the session
            this.configuration.setSessionNonce(nonce.getValue());
        }

        // Claims
        requestBuilder.claims(this.configuration.getClaimsRequest());

        // State
        requestBuilder.state(state);

        // Prompt
        requestBuilder.prompt(prompt);

        // PKCE
        CodeVerifier codeVerifier = new CodeVerifier();
        this.configuration.setSessionCodeVerifier(codeVerifier);
        requestBuilder.codeChallenge(codeVerifier, CodeChallengeMethod.S256);

        // Remember this authorization in case another one is started from the same session before the provider answers
        this.configuration.savePendingAuthorization(state.getValue());

        // Redirect the user to the provider
        String redirectURL = requestBuilder.build().toURI().toString();
        LOGGER.debug("Redirecting the user to [{}]", redirectURL);
        this.manager.redirect(redirectURL, true);
    }

    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key)
    {
        String value = request.get(key);

        if (value != null) {
            this.configuration.setSessionAttribute(key, value);
        }
    }

    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key, Type targetType)
    {
        String value = request.get(key);

        if (value != null) {
            this.configuration.setSessionAttribute(key, this.converter.convert(targetType, value));
        }
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        if (!this.configuration.isSkipped()) {
            // It does not make much sense redirecting in the case of an ajax call as most of the time the redirect will
            // fail (if CORS are not allowed on the target OIDC provider)
            if (!Utils.isAjaxRequest(context)) {
                try {
                    showLoginOIDC(context);
                } catch (Exception e) {
                    LOGGER.error("Failed to show OpenID Connect login", e);

                    // Fallback on standard auth
                    super.showLogin(context);
                }
            }
        } else {
            super.showLogin(context);
        }
    }
}
