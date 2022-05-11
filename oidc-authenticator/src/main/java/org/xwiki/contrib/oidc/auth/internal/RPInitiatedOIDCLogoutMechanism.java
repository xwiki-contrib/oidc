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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.InstantiationStrategy;
import org.xwiki.component.descriptor.ComponentInstantiationStrategy;
import org.xwiki.contrib.oidc.auth.OIDCLogoutMechanism;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.xpn.xwiki.XWikiContext;

/**
 * Implements <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-initiated</a> logout mechanism.
 *
 * @version $Id$
 * @since 1.31
 */
@Component
@Named(RPInitiatedOIDCLogoutMechanism.LOGOUT_MECHANISM_NAME)
@InstantiationStrategy(ComponentInstantiationStrategy.PER_LOOKUP)
public class RPInitiatedOIDCLogoutMechanism implements OIDCLogoutMechanism
{
    /**
     * The logout mechanism name.
     */
    public static final String LOGOUT_MECHANISM_NAME = "rpInitiated";

    @Inject
    private OIDCClientConfiguration clientConfiguration;

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    private URI logoutURI;

    private IDTokenClaimsSet idTokenClaimsSet;

    private ClientID clientID;

    @Override
    public void prepareLogout()
    {
        try {
            this.logoutURI = this.clientConfiguration.getLogoutOIDCEndpoint().getURI();
        } catch (URISyntaxException e) {
            this.logger.error("Failed to prepare OIDC RP-initiated log-out.", e);
        }

        this.idTokenClaimsSet = this.clientConfiguration.getIdToken();
        this.clientID = this.clientConfiguration.getClientID();
    }

    @Override
    public void logout()
    {
        XWikiContext context = contextProvider.get();

        if (this.logoutURI != null && this.idTokenClaimsSet != null && this.clientID != null) {
            try {
                URL serverURL = context.getURLFactory().getServerURL(context);
                URIBuilder xredirectBuilder = new URIBuilder(serverURL.toURI());
                xredirectBuilder.removeQuery();

                URIBuilder logoutBuilder = new URIBuilder(logoutURI);
                logoutBuilder.addParameter("client_id", this.clientID.getValue());
                logoutBuilder.addParameter("logout_uri", xredirectBuilder.build().toString());

                context.getResponse().sendRedirect(logoutBuilder.build().toString());
                context.setFinished(true);
            } catch (URISyntaxException | IOException e) {
                this.logger.error("Failed to perform OIDC RP-initiated log-out.", e);
            }
        }
    }
}
