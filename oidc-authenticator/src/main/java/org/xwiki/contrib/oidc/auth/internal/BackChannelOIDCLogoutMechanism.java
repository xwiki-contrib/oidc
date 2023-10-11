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

import javax.inject.Inject;
import javax.inject.Named;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.InstantiationStrategy;
import org.xwiki.component.descriptor.ComponentInstantiationStrategy;
import org.xwiki.contrib.oidc.auth.OIDCLogoutException;
import org.xwiki.contrib.oidc.auth.OIDCLogoutMechanism;

import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Implements <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">back-channel</a> logout mechanism.
 *
 * @version $Id$
 * @since 1.31
 */
@Component
@Named(BackChannelOIDCLogoutMechanism.LOGOUT_MECHANISM_NAME)
@InstantiationStrategy(ComponentInstantiationStrategy.PER_LOOKUP)
public class BackChannelOIDCLogoutMechanism implements OIDCLogoutMechanism
{
    /**
     * The logout mechanism name.
     */
    public static final String LOGOUT_MECHANISM_NAME = "backChannel";

    @Inject
    private Logger logger;

    @Inject
    private OIDCClientConfiguration configuration;

    private Endpoint logoutURI;

    private IDTokenClaimsSet idTokenClaimsSet;

    @Override
    public void prepareLogout() throws OIDCLogoutException
    {
        try {
            this.logoutURI = this.configuration.getLogoutOIDCEndpoint();
        } catch (Exception e) {
            throw new OIDCLogoutException("Failed to generate the logout endpoint URI", e);
        }

        this.idTokenClaimsSet = this.configuration.getIdToken();
    }

    @Override
    public void logout() throws OIDCLogoutException
    {
        if (this.logoutURI != null) {
            try {
                // TODO : Issue an exception if the logout doesn't work. So far we are only getting an HTTP error
                //  code that is not handled.
                sendBackChannelLogout();
            } catch (Exception e) {
                throw new OIDCLogoutException("Failed to send logout request", e);
            }
        } else {
            this.logger.debug("Don't send OIDC logout request: no OIDC logout URI set");
        }
    }

    private int sendBackChannelLogout()
        throws IOException, ParseException
    {
        LogoutRequest logoutRequest =
            new LogoutRequest(this.logoutURI.getURI(), new PlainJWT(this.idTokenClaimsSet.toJWTClaimsSet()));

        HTTPRequest logoutHTTP = logoutRequest.toHTTPRequest();

        this.logoutURI.prepare(logoutHTTP);
        this.logger.debug("OIDC logout request ({}?{},{})", logoutHTTP.getURL(), logoutHTTP.getURL(),
            logoutHTTP.getHeaderMap());
        HTTPResponse httpResponse = logoutHTTP.send();
        this.logger.debug("OIDC logout response ({})", httpResponse.getBody());

        return httpResponse.getStatusCode();
    }
}
