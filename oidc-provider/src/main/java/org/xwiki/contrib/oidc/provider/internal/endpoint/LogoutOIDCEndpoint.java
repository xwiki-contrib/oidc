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

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.util.EmptyResponse;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * Provider Logout set endpoint for OpenID Connect.
 * <p>
 * Related specifications:
 * <ul>
 * <li>OpenID Connect RP-Initiated Logout 1.0, section 2. https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 * </ul>
 * 
 * @version $Id$
 * @since 2.4.0
 */
@Component
@Named(LogoutOIDCEndpoint.HINT)
@Singleton
public class LogoutOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "logout";

    private static final String LOGOUT_ACTION = HINT;

    @Inject
    private OIDCManager manager;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        LogoutRequest request = LogoutRequest.parse(httpRequest);

        XWikiContext xcontext = xcontextProvider.get();

        // Authenticate
        XWikiUser user = xcontext.getWiki().checkAuth(xcontext);

        // If the user is authenticated, log out
        if (user != null) {
            // Set context user
            xcontext.setUser(user.getUser());

            // Logout clients
            this.manager.logoutSessions(xcontext.getUserReference());

            // Redirect to standard local logout (and back, if there is a post logout indicated in the request)
            String xredirect = null;
            if (request.getPostLogoutRedirectionURI() != null) {
                LogoutRequest xredirectLogout =
                    LogoutRequest.parse(this.manager.createEndPointURI(HINT), request.toQueryString());
                xredirect =
                    "xredirect=" + URLEncoder.encode(xredirectLogout.toURI().toString(), StandardCharsets.UTF_8);
            }
            String logoutURL =
                xcontext.getWiki().getExternalURL("XWiki.XWikiLogout", LOGOUT_ACTION, xredirect, xcontext);
            return new RedirectResponse(new URI(logoutURL));
        }

        // Redirect if specified in the request
        if (request.getPostLogoutRedirectionURI() != null) {
            return new RedirectResponse(request.getPostLogoutRedirectionURI());
        }

        return EmptyResponse.OK;
    }
}
