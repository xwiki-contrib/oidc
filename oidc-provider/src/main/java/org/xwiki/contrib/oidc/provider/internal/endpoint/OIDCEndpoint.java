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

import org.xwiki.component.annotation.Role;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

/**
 * OpenID Connect endpoint.
 * 
 * @version $Id$
 */
@Role
public interface OIDCEndpoint
{
    /**
     * Handle the request and return a {@link Response}.
     * 
     * @param httpRequest the HTTP request
     * @param reference the reference generated from the request
     * @return the {@link Response}
     * @throws Exception when failing to handle the request
     */
    Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception;
}
