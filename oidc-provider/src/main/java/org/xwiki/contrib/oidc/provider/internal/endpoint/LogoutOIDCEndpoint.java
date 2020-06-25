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

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.LogoutRequest;

/**
 * Provider Logout set endpoint for OpenID Connect.
 *
 * @version $Id$
 */
@Component
@Named(LogoutOIDCEndpoint.HINT)
@Singleton
// TODO
public class LogoutOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "logout";

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        LogoutRequest request = LogoutRequest.parse(httpRequest);

        // LogoutResponse
        return null;
    }
}
