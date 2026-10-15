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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCRequestFilter}.
 *
 * @version $Id$
 */
@ComponentTest
class OIDCRequestFilterTest
{
    private static final String ORIGIN = "https://client.example.com";

    @InjectMockComponents
    private OIDCRequestFilter filter;

    @MockComponent
    private OIDCProviderConfiguration configuration;

    private HttpServletRequest request = mock(HttpServletRequest.class);

    private HttpServletResponse response = mock(HttpServletResponse.class);

    @BeforeEach
    void beforeEach()
    {
        when(this.configuration.getCORSAllowedOrigins()).thenReturn(List.of(OIDCProviderConfiguration.CORS_ANY_ORIGIN));
    }

    private static OIDCEndpoint endpoint(boolean corsAllowed)
    {
        OIDCEndpoint endpoint = mock(OIDCEndpoint.class);
        when(endpoint.isCORSAllowed()).thenReturn(corsAllowed);

        return endpoint;
    }

    @Test
    void preflight()
    {
        when(this.request.getMethod()).thenReturn("OPTIONS");
        when(this.request.getHeader("Origin")).thenReturn(ORIGIN);
        when(this.request.getHeader("Access-Control-Request-Method")).thenReturn("GET");

        assertTrue(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response).setStatus(HttpServletResponse.SC_NO_CONTENT);
        verify(this.response).setHeader("Access-Control-Allow-Origin", "*");
        verify(this.response).setHeader("Access-Control-Allow-Methods", "GET, POST");
        verify(this.response).setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        verify(this.response).setHeader("Access-Control-Max-Age", "86400");
        verify(this.response).setHeader("Allow", "GET, POST, OPTIONS");
        verify(this.response, never()).setHeader(eq("Access-Control-Allow-Credentials"), anyString());
        verify(this.response, never()).addHeader(eq("Vary"), anyString());
    }

    @Test
    void getWithOrigin()
    {
        when(this.request.getMethod()).thenReturn("GET");
        when(this.request.getHeader("Origin")).thenReturn(ORIGIN);

        assertFalse(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response).setHeader("Access-Control-Allow-Origin", "*");
        verify(this.response).setHeader("Access-Control-Expose-Headers", "WWW-Authenticate");
        verify(this.response, never()).setHeader(eq("Access-Control-Allow-Methods"), anyString());
        verify(this.response, never()).setStatus(anyInt());
    }

    @Test
    void getWithoutOrigin()
    {
        when(this.request.getMethod()).thenReturn("GET");

        assertFalse(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response, never()).setHeader(anyString(), anyString());
        verify(this.response, never()).setStatus(anyInt());
    }

    @Test
    void postWithAllowedOrigin()
    {
        when(this.configuration.getCORSAllowedOrigins()).thenReturn(List.of("https://other.example.com", ORIGIN));
        when(this.request.getMethod()).thenReturn("POST");
        when(this.request.getHeader("Origin")).thenReturn(ORIGIN);

        assertFalse(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response).setHeader("Access-Control-Allow-Origin", ORIGIN);
        verify(this.response).addHeader("Vary", "Origin");
    }

    @Test
    void preflightWithForbiddenOrigin()
    {
        when(this.configuration.getCORSAllowedOrigins()).thenReturn(List.of("https://other.example.com"));
        when(this.request.getMethod()).thenReturn("OPTIONS");
        when(this.request.getHeader("Origin")).thenReturn(ORIGIN);
        when(this.request.getHeader("Access-Control-Request-Method")).thenReturn("GET");

        assertTrue(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response).setStatus(HttpServletResponse.SC_NO_CONTENT);
        verify(this.response).addHeader("Vary", "Origin");
        verify(this.response, never()).setHeader(eq("Access-Control-Allow-Origin"), anyString());
        verify(this.response, never()).setHeader(eq("Access-Control-Allow-Methods"), anyString());
    }

    @Test
    void preflightWithCORSDisabled()
    {
        when(this.configuration.getCORSAllowedOrigins()).thenReturn(List.of());
        when(this.request.getMethod()).thenReturn("OPTIONS");
        when(this.request.getHeader("Origin")).thenReturn(ORIGIN);
        when(this.request.getHeader("Access-Control-Request-Method")).thenReturn("GET");

        assertTrue(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response, never()).setHeader(eq("Access-Control-Allow-Origin"), anyString());
    }

    @Test
    void optionsWithoutCORS()
    {
        when(this.request.getMethod()).thenReturn("OPTIONS");
        when(this.request.getHeader("Origin")).thenReturn(ORIGIN);

        assertTrue(this.filter.filter(endpoint(false), this.request, this.response));

        verify(this.response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verify(this.response).setHeader("Allow", "GET, POST");
        verify(this.response, never()).setHeader(eq("Access-Control-Allow-Origin"), anyString());
    }

    @Test
    void unsupportedMethod()
    {
        when(this.request.getMethod()).thenReturn("TRACE");

        assertTrue(this.filter.filter(endpoint(true), this.request, this.response));

        verify(this.response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verify(this.response).setHeader("Allow", "GET, POST, OPTIONS");
    }

    @Test
    void getWithoutCORS()
    {
        when(this.request.getMethod()).thenReturn("GET");

        assertFalse(this.filter.filter(endpoint(false), this.request, this.response));

        verify(this.response, never()).setStatus(anyInt());
    }
}
