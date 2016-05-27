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
package com.xwiki.oidc.auth;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.properties.ConverterManager;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;
import com.xwiki.oidc.auth.internal.OIDCClientConfiguration;
import com.xwiki.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;

/**
 * Authenticate user trough an OpenId Connect provider.
 * 
 * @version $Id$
 */
public class OIDCAuthServiceImpl extends XWikiAuthServiceImpl
{
    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCAuthServiceImpl.class);

    /**
     * Used to convert a string into a proper Document Name.
     */
    private DocumentReferenceResolver<String> currentDocumentReferenceResolver =
        Utils.getComponent(DocumentReferenceResolver.TYPE_STRING, "current");

    /**
     * Used to convert a Document Reference to a username to a string. Note that we must be careful not to include the
     * wiki name as part of the serialized name since user names are saved in the database (for example as the document
     * author when you create a new document) and we're only supposed to save the wiki part when the user is from
     * another wiki. This should probably be fixed in the future though but it requires changing existing code that
     * depend on this behavior.
     */
    private EntityReferenceSerializer<String> compactWikiEntityReferenceSerializer =
        Utils.getComponent(EntityReferenceSerializer.TYPE_STRING, "compactwiki");

    private OIDCManager oidc = Utils.getComponent(OIDCManager.class);

    private OIDCClientConfiguration configuration = Utils.getComponent(OIDCClientConfiguration.class);

    private OIDCManager manager = Utils.getComponent(OIDCManager.class);

    private ConverterManager converter = Utils.getComponent(ConverterManager.class);

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        // Check if there is already a user in the session, take care of logout, etc.
        XWikiUser user = super.checkAuth(context);

        // Try OIDC if there is not already authenticated user
        if (user == null) {
            try {
                checkAuthOIDC(context);
            } catch (Exception e) {
                throw new XWikiException("Failed OIDC authentication", e);
            }
        }

        return user;
    }

    private void checkAuthOIDC(XWikiContext context) throws Exception
    {
        // Check if OIDC is skipped or not and remember it
        if (this.configuration.isSkipped()) {
            maybeStoreRequestParameterInSession(context.getRequest(), OIDCClientConfiguration.PROP_SKIPPED,
                Boolean.class);

            return;
        } else {
            maybeStoreRequestParameterInSession(context.getRequest(), OIDCClientConfiguration.PROP_SKIPPED,
                Boolean.class);
        }

        // If the URL contain a OIDC provider, assume it was asked to the user
        String provider = context.getRequest().getParameter(OIDCClientConfiguration.PROP_PROVIDER);
        if (provider != null) {
            authenticate(context);

            return;
        }

        // Ugly but there is no other way for an authenticator to be called when someone request to login...
        if (context.getAction().equals("login")) {
            showLoginOIDC(context);
        }
    }

    private void showLoginOIDC(XWikiContext context) throws Exception
    {
        // Check endpoints
        URI endpoint = this.configuration.getAuthorizationOIDCEndpoint();

        // If no endpoint can be found, ask for it
        if (endpoint == null) {
            this.manager.executeTemplate("oidc/client/provider.vm", context.getResponse());
            context.setFinished(true);
            return;
        }

        authenticate(context);
    }

    private void authenticate(XWikiContext context) throws XWikiException, URISyntaxException, IOException
    {
        // Generate callback URL
        URI callback = this.oidc.createEndPointURI(CallbackOIDCEndpoint.HINT);

        // Remember the current URL
        URL requestURL = XWiki.getRequestURL(context.getRequest());
        // TODO: add also the session id to make it a bit more unique
        State state = new State(requestURL.toString());

        // Remember various stuff in the session so that callback can access it
        XWikiRequest request = context.getRequest();
        request.getSession().setAttribute(OIDCClientConfiguration.PROP_STATE, state);
        request.getSession().setAttribute(OIDCClientConfiguration.PROP_INITIAL_REQUEST, requestURL);
        maybeStoreRequestParameterURLInSession(request, OIDCClientConfiguration.PROP_PROVIDER);
        maybeStoreRequestParameterInSession(request, OIDCClientConfiguration.PROP_USER_NAMEFORMATER);
        maybeStoreRequestParameterURLInSession(request, OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION);
        maybeStoreRequestParameterURLInSession(request, OIDCClientConfiguration.PROP_ENDPOINT_TOKEN);
        maybeStoreRequestParameterURLInSession(request, OIDCClientConfiguration.PROP_ENDPOINT_USERINFO);

        // Create the request URL
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL,
            OIDCScopeValue.ADDRESS, OIDCScopeValue.PHONE);
        ClientID clientID = new ClientID(this.configuration.getClientID());
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        AuthenticationRequest.Builder requestBuilder =
            new AuthenticationRequest.Builder(responseType, scope, clientID, callback);
        requestBuilder.endpointURI(this.configuration.getAuthorizationOIDCEndpoint());
        requestBuilder.state(state);

        // Redirect the user to the provider
        context.getResponse().sendRedirect(requestBuilder.build().toURI().toString());
    }

    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key)
    {
        String value = request.get(key);

        if (value != null) {
            request.getSession().setAttribute(key, value);
        }
    }

    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key, Type targetType)
    {
        String value = request.get(key);

        if (value != null) {
            request.getSession().setAttribute(key, this.converter.convert(targetType, value));
        }
    }

    private void maybeStoreRequestParameterURLInSession(XWikiRequest request, String key) throws MalformedURLException
    {
        String value = request.get(key);

        if (value != null) {
            request.getSession().setAttribute(key, new URL(value));
        }
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        if (!this.configuration.isSkipped()) {
            // TODO: allow skipping OIDC (for example in the provider page)
            try {
                showLoginOIDC(context);
            } catch (Exception e) {
                LOGGER.error("Failed to show OpenId Connect login", e);

                // Fallback on standard auth
                super.showLogin(context);
            }
        } else {
            super.showLogin(context);
        }
    }
}
