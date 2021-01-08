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

import java.net.URI;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

/**
 * Represent an endpoint {@link URI} and associated metadata (HTTP headers, etc.).
 * 
 * @version $Id$
 * @since 1.22
 */
public class Endpoint
{
    private final URI uri;

    private final Map<String, List<String>> headers;

    /**
     * @param uri the URI
     * @param headers the custom headers to send with the endpoint
     */
    public Endpoint(URI uri, Map<String, List<String>> headers)
    {
        this.uri = uri;
        this.headers = headers;
    }

    /**
     * @param request the request to complete
     * @return inject custom headers to the passed request
     */
    public HTTPRequest prepare(HTTPRequest request)
    {
        // Set custom headers
        request.getHeaderMap().putAll(this.headers);

        // Set a proper user agent
        request.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
            + this.getClass().getPackage().getImplementationVersion());

        return request;
    }

    /**
     * @return the uri
     */
    public URI getURI()
    {
        return this.uri;
    }

    /**
     * @return the headers
     */
    public Map<String, List<String>> getHeaders()
    {
        return this.headers;
    }
}
