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
package org.xwiki.contrib.oidc.provider.internal.util;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

/**
 * Implementation of {@link Response} which return a simple content.
 * 
 * @version $Id$
 * @since 2.4.0
 */
public class EmptyResponse implements Response
{
    /**
     * Indicate the request succeeded.
     */
    public static final EmptyResponse OK = new EmptyResponse(HTTPResponse.SC_OK);

    /**
     * Indicate a bad request.
     */
    public static final EmptyResponse BAD_REQUEST = new EmptyResponse(HTTPResponse.SC_BAD_REQUEST);

    private final HTTPResponse httpResponse;

    /**
     * @param statusCode the status code to return
     */
    public EmptyResponse(int statusCode)
    {
        this.httpResponse = new HTTPResponse(statusCode);
    }

    @Override
    public HTTPResponse toHTTPResponse()
    {
        return this.httpResponse;
    }

    @Override
    public boolean indicatesSuccess()
    {
        return true;
    }
}
