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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.container.servlet.ServletResponse;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCSilentReauthentication}.
 *
 * @version $Id$
 */
@ComponentTest
class OIDCSilentReauthenticationTest
{
    @MockComponent
    private Container container;

    @MockComponent
    private OIDCClientConfiguration configuration;

    @InjectMockComponents
    private OIDCSilentReauthentication silentReauthentication;

    private HttpServletRequest request;

    private HttpServletResponse response;

    @BeforeEach
    void beforeEach()
    {
        this.request = mock(HttpServletRequest.class);
        when(this.request.getContextPath()).thenReturn("/xwiki");
        when(this.request.getMethod()).thenReturn("GET");
        when(this.request.getHeader("Accept")).thenReturn("text/html,application/xhtml+xml,*/*;q=0.8");

        HttpSession session = mock(HttpSession.class);
        Map<String, Object> attributes = new HashMap<>();
        when(session.getAttribute(anyString())).then(invocation -> attributes.get(invocation.getArgument(0)));
        doAnswer(invocation -> attributes.put(invocation.getArgument(0), invocation.getArgument(1))).when(session)
            .setAttribute(anyString(), any());
        when(this.request.getSession()).thenReturn(session);

        when(this.container.getRequest()).thenReturn(new ServletRequest(this.request));

        this.response = mock(HttpServletResponse.class);
        when(this.container.getResponse()).thenReturn(new ServletResponse(this.response));

        when(this.configuration.isSilentReauthenticationEnabled()).thenReturn(true);
        when(this.configuration.getSilentReauthenticationCookieMaxAge()).thenReturn(3600);
    }

    private void withCookie()
    {
        when(this.request.getCookies())
            .thenReturn(new Cookie[] { new Cookie("other", "value"),
                new Cookie(OIDCSilentReauthentication.COOKIE_NAME, "1") });
    }

    private Cookie addedCookie()
    {
        ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(this.response).addCookie(captor.capture());

        return captor.getValue();
    }

    @Test
    void onLogin()
    {
        this.silentReauthentication.onLogin();

        Cookie cookie = addedCookie();
        assertEquals(OIDCSilentReauthentication.COOKIE_NAME, cookie.getName());
        assertEquals(3600, cookie.getMaxAge());
        assertEquals("/xwiki", cookie.getPath());
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    void onLoginWhenDisabled()
    {
        when(this.configuration.isSilentReauthenticationEnabled()).thenReturn(false);

        this.silentReauthentication.onLogin();

        verify(this.response, never()).addCookie(any());
    }

    @Test
    void forget()
    {
        withCookie();

        this.silentReauthentication.forget();

        Cookie cookie = addedCookie();
        assertEquals(OIDCSilentReauthentication.COOKIE_NAME, cookie.getName());
        assertEquals(0, cookie.getMaxAge());
    }

    @Test
    void forgetWithoutCookie()
    {
        this.silentReauthentication.forget();

        verify(this.response, never()).addCookie(any());
    }

    @Test
    void startAttemptOncePerSession()
    {
        withCookie();

        assertTrue(this.silentReauthentication.startAttempt());
        assertFalse(this.silentReauthentication.startAttempt());
    }

    @Test
    void startAttemptWithoutCookie()
    {
        assertFalse(this.silentReauthentication.startAttempt());
    }

    @Test
    void startAttemptWhenDisabled()
    {
        withCookie();
        when(this.configuration.isSilentReauthenticationEnabled()).thenReturn(false);

        assertFalse(this.silentReauthentication.startAttempt());
    }

    @Test
    void startAttemptForAjaxRequest()
    {
        withCookie();
        when(this.request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");

        assertFalse(this.silentReauthentication.startAttempt());

        // The attempt was not consumed
        when(this.request.getHeader("X-Requested-With")).thenReturn(null);
        assertTrue(this.silentReauthentication.startAttempt());
    }

    @Test
    void startAttemptForResource()
    {
        withCookie();
        when(this.request.getHeader("Accept")).thenReturn("image/avif,image/webp,*/*");

        assertFalse(this.silentReauthentication.startAttempt());
    }

    @Test
    void startAttemptForPost()
    {
        withCookie();
        when(this.request.getMethod()).thenReturn("POST");

        assertFalse(this.silentReauthentication.startAttempt());
    }
}
