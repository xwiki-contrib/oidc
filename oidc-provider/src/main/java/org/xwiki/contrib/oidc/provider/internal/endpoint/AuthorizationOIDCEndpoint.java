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
package org.xwiki.contrib.oidc.provider.internal.endpoint;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.script.ScriptContext;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsentClassDocumentInitializer;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.contrib.oidc.provider.internal.util.StoreUtils;
import org.xwiki.csrf.CSRFToken;
import org.xwiki.script.ScriptContextManager;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * Authorization endpoint for OpenId Connect.
 * 
 * @version $Id$
 */
@Component
@Named(AuthorizationOIDCEndpoint.HINT)
@Singleton
public class AuthorizationOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "authorization";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private OIDCStore store;

    @Inject
    private OIDCManager manager;

    @Inject
    private CSRFToken csrf;

    @Inject
    private ScriptContextManager scripts;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        AuthenticationRequest request = AuthenticationRequest.parse(httpRequest);

        XWikiContext xcontext = this.xcontextProvider.get();

        JWT idToken = null;

        ///////////////////////////////////////////////////////
        // Authentication
        ///////////////////////////////////////////////////////

        // Authenticate
        XWikiUser user = xcontext.getWiki().checkAuth(xcontext);
        if (user == null) {
            if (prompt(request, Prompt.Type.NONE)) {
                // Interactive login is disabled but the user was not automatically authenticated
                return new AuthenticationErrorResponse(request.getRedirectionURI(), OIDCError.INTERACTION_REQUIRED,
                    request.getState(), null);
            }

            xcontext.getWiki().getAuthService().showLogin(xcontext);

            return null;
        } else if (prompt(request, Prompt.Type.LOGIN)) {
            // Login is forced by the client
            xcontext.getWiki().getAuthService().showLogin(xcontext);

            return null;
        }

        // Set context user
        xcontext.setUser(user.getUser());

        ///////////////////////////////////////////////////////
        // Consent
        ///////////////////////////////////////////////////////

        // Required to look up the client in the provider's database
        ClientID clientID = request.getClientID();

        // Get current consent for provided client id
        OIDCConsent consent = this.store.getConsent(clientID, request.getRedirectionURI(), null);

        // Check if consent is already granted
        if (consent == null || prompt(request, Prompt.Type.CONSENT)) {
            // Impossible to validate consent without user interaction
            if (prompt(request, Prompt.Type.NONE)) {
                return new AuthenticationErrorResponse(request.getRedirectionURI(), OIDCError.CONSENT_REQUIRED,
                    request.getState(), null);
            }

            // Ask user for consent
            Boolean consentAnswer = getConsent(httpRequest);
            if (consentAnswer == null) {
                return askConsent(request, httpRequest);
            } else if (!consentAnswer) {
                return new AuthenticationErrorResponse(request.getRedirectionURI(), OAuth2Error.UNAUTHORIZED_CLIENT,
                    request.getState(), null);
            }

            // Create new consent
            consent = StoreUtils.newCustomObject(this.store.getUserDocument(),
                OIDCConsentClassDocumentInitializer.REFERENCE, xcontext, OIDCConsent.class);

            // TODO: store the claims in the consent

            consent.setClientID(clientID);
            consent.setRedirectURI(request.getRedirectionURI());

            // Generate authorization code or tokens depending on the response type
            if (request.getResponseType().impliesCodeFlow()) {
                consent.setAuthorizationCode(new AuthorizationCode());
                consent.setAccessToken(null);
            } else if (request.getResponseType().impliesImplicitFlow()) {
                consent.setAuthorizationCode(null);
                consent.setAccessToken(new BearerAccessToken());
                idToken = this.manager.createdIdToken(clientID, consent.getUserReference(), request.getNonce());
            }

            // Save consent
            this.store.saveConsent(consent, "Add new OIDC consent");
        } else {
            // Generate id token in case of implicit flow
            if (request.getResponseType().impliesImplicitFlow()) {
                idToken = this.manager.createdIdToken(clientID, consent.getUserReference(), request.getNonce());
            }
        }

        // Create response
        return new AuthenticationSuccessResponse(request.getRedirectionURI(), consent.getAuthorizationCode(), idToken,
            consent.getAccessToken(), request.getState(), null, null);
    }

    private boolean prompt(AuthenticationRequest request, Prompt.Type type)
    {
        return request.getPrompt() != null ? request.getPrompt().contains(type) : false;
    }

    private Boolean getConsent(HTTPRequest httpRequest)
    {
        Map<String, String> parameters = httpRequest.getQueryParameters();

        // The user explicitly refused access to the client
        if (parameters.get("consent_refuse") != null) {
            return false;
        }

        // Check if user explicitly gave consent to the client
        if (parameters.get("consent_accept") != null) {
            String token = parameters.get("form_token");
            if (this.csrf.isTokenValid(token)) {
                return true;
            } else {
                // Looks like some client tried to hack consent
                // TODO: log something ? ban the client ?
            }
        }

        // Ask for user consent
        return null;
    }

    private Response askConsent(AuthenticationRequest request, HTTPRequest httpRequest) throws Exception
    {
        // Set various information in the script context
        Map<String, Object> oidc = new HashMap<>();
        oidc.put("request", request);
        oidc.put("httprequest", httpRequest);
        this.scripts.getScriptContext().setAttribute("oidc", oidc, ScriptContext.ENGINE_SCOPE);

        return this.manager.executeTemplate("oidc/provider/consent.vm", request);
    }
}
