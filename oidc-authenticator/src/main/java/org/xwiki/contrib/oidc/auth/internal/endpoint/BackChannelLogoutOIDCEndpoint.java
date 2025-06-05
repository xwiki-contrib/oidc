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
package org.xwiki.contrib.oidc.auth.internal.endpoint;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.session.ClientHttpSessions;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders.ClientProvider;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.EmptyResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.BackChannelLogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenClaimsVerifier;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenValidator;

/**
 * Back-channel logout endpoint.
 * <p>
 * Related specifications:
 * <ul>
 * <li>OpenID Connect Back-Channel Logout 1.0, section 2.5 (draft 07).
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 * </ul>
 * 
 * @version $Id$
 */
@Component
@Named(BackChannelLogoutOIDCEndpoint.HINT)
@Singleton
public class BackChannelLogoutOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "authenticator/backchannel_logout";

    @Inject
    private ClientHttpSessions sessions;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCManager oidc;

    @Inject
    private Logger logger;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        this.logger.debug("OIDC backchannel_logout: starting with request [{}]", httpRequest.getURL());

        // Parse the request
        BackChannelLogoutRequest logoutRequest = BackChannelLogoutRequest.parse(httpRequest);

        // Parse and validate the logout token
        ClientProvider clientProvider = this.configuration.getClientProvider();
        LogoutTokenClaimsSet logoutToken;
        if (clientProvider != null) {
            JWT jwt = logoutRequest.getLogoutToken();

            LogoutTokenValidator tokenValidator = LogoutTokenValidator.create(clientProvider.getMetadata(),
                this.configuration.createClientInformation(jwt), this.oidc.getJWKSource());

            logoutToken = validate(tokenValidator, jwt);
        } else {
            // TODO: add support for null ClientProvider
            logoutToken = new LogoutTokenClaimsSet(logoutRequest.getLogoutToken().getJWTClaimsSet());
        }

        // Logout all sessions associated with the indicated user
        this.sessions.logout(logoutToken.getSubject());

        return EmptyResponse.OK;
    }

    private LogoutTokenClaimsSet validate(LogoutTokenValidator tokenValidator, JWT logoutToken)
        throws BadJOSEException, JOSEException, ParseException
    {
        // Workaround a bug in Keycloak which sent the wrong type (see
        // https://github.com/keycloak/keycloak/issues/19220)
        if (logoutToken.getHeader().getType() == null
            || logoutToken.getHeader().getType().equals(LogoutTokenValidator.TYPE)) {
            return tokenValidator.validate(logoutToken);
        } else {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSTypeVerifier(new JOSEObjectTypeVerifier<SecurityContext>()
            {
                @Override
                public void verify(JOSEObjectType type, SecurityContext context) throws BadJOSEException
                {
                    // Do nothing since the type is wrong (which suggests a mistake of the provider)
                }
            });
            jwtProcessor.setJWSKeySelector(tokenValidator.getJWSKeySelector());
            jwtProcessor.setJWTClaimsSetVerifier(
                new LogoutTokenClaimsVerifier(tokenValidator.getExpectedIssuer(), tokenValidator.getClientID()));
            JWTClaimsSet jwtClaimsSet = jwtProcessor.process(logoutToken, null);

            return new LogoutTokenClaimsSet(jwtClaimsSet);
        }
    }
}
