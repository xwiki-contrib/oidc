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
package org.xwiki.contrib.oidc.internal;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.context.concurrent.ContextStoreManager;
import org.xwiki.contrib.oidc.OAuth2ClientManager;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.OAuth2Token;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.job.DefaultRequest;
import org.xwiki.job.Job;
import org.xwiki.job.JobExecutor;
import org.xwiki.model.reference.EntityReferenceSerializer;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;

import static org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION_PROPERTY;
import static org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration.PROP_IS_USED_FOR_AUTHENTICATION;

/**
 * Default manager implementation for OAuth2 clients.
 *
 * @version $Id$
 * @since 2.15.0
 */
@Component
@Singleton
public class DefaultOAuth2ClientManager implements OAuth2ClientManager
{
    @Inject
    private OIDCManager oidcManager;

    @Inject
    private OAuth2TokenStore tokenStore;

    @Inject
    private org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration authConfig;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private ContextStoreManager contextStoreManager;

    @Inject
    private Logger logger;

    @Inject
    private JobExecutor executor;

    @Override
    public void authorize(OIDCClientConfiguration config, URI redirectURI) throws OAuth2Exception
    {
        try {
            // Clear the OIDC session to remove any information that could be coming from previous authorizations.
            this.authConfig.getOIDCSession(true).clear();

            // Generate unique state, populate the session
            State state = new State();
            this.authConfig.setSessionState(state.getValue());
            this.authConfig.setSessionAttribute(DEFAULT_CLIENT_CONFIGURATION_PROPERTY, config.getConfigurationName());
            this.authConfig.setSessionAttribute(PROP_IS_USED_FOR_AUTHENTICATION, false);
            this.authConfig.setSuccessRedirectURI(redirectURI);

            ResponseType responseType = new ResponseType(config.getResponseType().toArray(new String[0]));
            ClientID clientId = new ClientID(config.getClientId());

            Scope scope = (config.getScope() != null)
                ? new Scope(config.getScope().toArray(new String[0])) : new Scope();

            // Create the request URL
            AuthorizationRequest.Builder requestBuilder =
                new AuthorizationRequest.Builder(responseType, clientId)
                    .redirectionURI(this.oidcManager.createEndPointURI(CallbackOIDCEndpoint.HINT))
                    .state(state)
                    .scope(scope)
                    .endpointURI(this.authConfig.getAuthorizationOIDCEndpoint().getURI());

            // Redirect the user to the provider
            String redirectURL = requestBuilder.build().toURI().toString();
            logger.debug("Redirecting the user to [{}]", redirectURL);
            this.oidcManager.redirect(redirectURL, true);

        } catch (URISyntaxException | IOException | GeneralException e) {
            throw new OAuth2Exception("Failed to perform authorization request", e);
        }
    }

    @Override
    public Job renew(OIDCClientConfiguration config) throws OAuth2Exception
    {
        return renew(config, false);
    }

    @Override
    public Job renew(OIDCClientConfiguration config, boolean force) throws OAuth2Exception
    {
        return renew(tokenStore.getToken(config), force);
    }

    @Override
    public Job renew(OAuth2Token token, boolean force) throws OAuth2Exception
    {
        // For now, only renew access tokens if they expire within the next 5 minutes.
        // TODO: Update the client configuration to allow users to define when a token should be renewed
        if (token instanceof NimbusOAuth2Token
            && (force || ((NimbusOAuth2Token) token).toAccessToken().getLifetime() < 60 * 5)) {
            DefaultRequest request = new DefaultRequest();
            request.setId("oauth2", token.getConfiguration().getConfigurationName(),
                entityReferenceSerializer.serialize(token.getReference()));
            request.setProperty(OAuth2TokenRenewalJob.TOKEN_PROPERTY, token);

            try {
                request.setContext(this.contextStoreManager.save(List.of("user")));

                return executor.execute(OAuth2TokenRenewalJob.JOB_TYPE, request);
            } catch (Exception e) {
                throw new OAuth2Exception(
                    String.format("Failed to renew token [%s]", token.getReference()), e);
            }
        } else if (token != null) {
            logger.info("Skipping renewal of token [{}] as the token is not close to expiry or is not supported.",
                token.getReference());
        }

        return null;
    }
}
