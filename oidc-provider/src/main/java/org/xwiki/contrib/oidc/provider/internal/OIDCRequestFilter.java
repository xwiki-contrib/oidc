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
package org.xwiki.contrib.oidc.provider.internal;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

/**
 * Handle the parts of the HTTP protocol which are not supported by the endpoints themselves: Cross Origin Resource
 * Sharing (CORS) and unsupported HTTP methods.
 * <p>
 * Only the endpoints indicating it with {@link OIDCEndpoint#isCORSAllowed()} support CORS. Those endpoints are not
 * expected to rely on cookies (they expect a bearer token or client credentials) so CORS credentials are never
 * allowed, which means a browser never sends the XWiki session cookie in a cross origin call.
 *
 * @version $Id$
 * @since 2.29.0
 */
@Component(roles = OIDCRequestFilter.class)
@Singleton
public class OIDCRequestFilter
{
    private static final String METHOD_OPTIONS = "OPTIONS";

    private static final String ALLOWED_METHODS = "GET, POST";

    private static final String ALLOWED_METHODS_CORS = ALLOWED_METHODS + ", " + METHOD_OPTIONS;

    private static final String ALLOWED_HEADERS = "Authorization, Content-Type";

    // Errors related to the bearer token are indicated in this header
    private static final String EXPOSED_HEADERS = "WWW-Authenticate";

    // 1 day
    private static final String MAX_AGE = "86400";

    private static final String HEADER_ORIGIN = "Origin";

    private static final String HEADER_ALLOW = "Allow";

    private static final String HEADER_VARY = "Vary";

    private static final String HEADER_REQUEST_METHOD = "Access-Control-Request-Method";

    private static final String HEADER_ALLOW_ORIGIN = "Access-Control-Allow-Origin";

    private static final String HEADER_ALLOW_METHODS = "Access-Control-Allow-Methods";

    private static final String HEADER_ALLOW_HEADERS = "Access-Control-Allow-Headers";

    private static final String HEADER_EXPOSE_HEADERS = "Access-Control-Expose-Headers";

    private static final String HEADER_MAX_AGE = "Access-Control-Max-Age";

    @Inject
    private OIDCProviderConfiguration configuration;

    /**
     * Add the CORS headers to the response and answer the requests which should not reach the endpoint.
     *
     * @param endpoint the target endpoint
     * @param request the HTTP request
     * @param response the HTTP response
     * @return {@code true} if the request was fully answered and should not be sent to the endpoint
     */
    public boolean filter(OIDCEndpoint endpoint, HttpServletRequest request, HttpServletResponse response)
    {
        boolean corsEndpoint = endpoint.isCORSAllowed();

        if (corsEndpoint) {
            applyCORS(request, response);

            if (METHOD_OPTIONS.equals(request.getMethod())) {
                // Pre-flight request (or a plain OPTIONS request): there is nothing more to say about the endpoint
                response.setHeader(HEADER_ALLOW, ALLOWED_METHODS_CORS);
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);

                return true;
            }
        }

        if (!isMethodSupported(request.getMethod())) {
            response.setHeader(HEADER_ALLOW, corsEndpoint ? ALLOWED_METHODS_CORS : ALLOWED_METHODS);
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);

            return true;
        }

        return false;
    }

    private boolean isMethodSupported(String method)
    {
        for (HTTPRequest.Method supportedMethod : HTTPRequest.Method.values()) {
            if (supportedMethod.name().equals(method)) {
                return true;
            }
        }

        return false;
    }

    private void applyCORS(HttpServletRequest request, HttpServletResponse response)
    {
        String origin = request.getHeader(HEADER_ORIGIN);

        if (StringUtils.isEmpty(origin)) {
            // Not a CORS request
            return;
        }

        List<String> allowedOrigins = this.configuration.getCORSAllowedOrigins();

        if (allowedOrigins.contains(OIDCProviderConfiguration.CORS_ANY_ORIGIN)) {
            response.setHeader(HEADER_ALLOW_ORIGIN, OIDCProviderConfiguration.CORS_ANY_ORIGIN);
        } else {
            // The answer depends on the origin so it should not be shared with requests from other origins by caches
            response.addHeader(HEADER_VARY, HEADER_ORIGIN);

            if (!allowedOrigins.contains(origin)) {
                // Without CORS headers, the browser won't give access to the response
                return;
            }

            response.setHeader(HEADER_ALLOW_ORIGIN, origin);
        }

        if (METHOD_OPTIONS.equals(request.getMethod()) && request.getHeader(HEADER_REQUEST_METHOD) != null) {
            response.setHeader(HEADER_ALLOW_METHODS, ALLOWED_METHODS);
            response.setHeader(HEADER_ALLOW_HEADERS, ALLOWED_HEADERS);
            response.setHeader(HEADER_MAX_AGE, MAX_AGE);
        } else {
            response.setHeader(HEADER_EXPOSE_HEADERS, EXPOSED_HEADERS);
        }
    }
}
