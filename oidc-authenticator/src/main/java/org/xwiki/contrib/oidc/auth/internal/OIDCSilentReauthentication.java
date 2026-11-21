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

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.Response;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.container.servlet.ServletResponse;

/**
 * Remember in a cookie that the browser was authenticated through OpenID Connect, so that the authentication can be
 * silently restarted (without any user interaction, the provider answering right away as long as its own session is
 * still alive) when the user comes back after the HTTP session expired. The cookie holds no credential: it only tells
 * that a silent authentication is worth attempting. Optionally, a silent authentication is attempted for every visitor,
 * so that the visitors already authenticated on the provider are authenticated right away.
 *
 * @version $Id$
 * @since 2.31.0
 */
@Component(roles = OIDCSilentReauthentication.class)
@Singleton
public class OIDCSilentReauthentication
{
    /**
     * The name of the cookie indicating that the browser was authenticated through OpenID Connect.
     */
    public static final String COOKIE_NAME = "oidcAuthenticated";

    /**
     * The name of the cookie indicating that the user explicitly logged out, in which case no silent authentication is
     * attempted until the browser is closed or the user logs in again.
     */
    public static final String LOGGED_OUT_COOKIE_NAME = "oidcLoggedOut";

    /**
     * The HTTP session attribute indicating that a silent re-authentication was already attempted in the session.
     */
    public static final String SESSION_ATTEMPTED = "oidc.silentReauthentication.attempted";

    @Inject
    private Container container;

    @Inject
    private OIDCClientConfiguration configuration;

    /**
     * Remember that the browser was authenticated through OpenID Connect.
     */
    public void onLogin()
    {
        if (this.configuration.isSilentReauthenticationEnabled()) {
            setCookie(COOKIE_NAME, "1", this.configuration.getSilentReauthenticationCookieMaxAge());
        }

        removeCookie(LOGGED_OUT_COOKIE_NAME);
    }

    /**
     * Forget that the browser was authenticated through OpenID Connect, when the provider cannot authenticate the user
     * without interaction anymore.
     */
    public void forget()
    {
        removeCookie(COOKIE_NAME);
    }

    /**
     * Forget that the browser was authenticated through OpenID Connect, and don't silently authenticate the user again
     * until the browser is closed or the user logs in again: the provider session might still be alive.
     */
    public void onLogout()
    {
        forget();

        // A browser session cookie
        setCookie(LOGGED_OUT_COOKIE_NAME, "1", -1);
    }

    /**
     * Indicate if a silent re-authentication should be started for the current request, and remember in the session
     * that it was, so that it's attempted only once per session.
     *
     * @return true if a silent re-authentication should be started for the current request
     */
    public boolean startAttempt()
    {
        HttpServletRequest request = getHttpServletRequest();
        if (request == null || !isDue(request) || !isPageNavigation(request)) {
            return false;
        }

        HttpSession session = request.getSession();
        if (session.getAttribute(SESSION_ATTEMPTED) != null) {
            return false;
        }
        session.setAttribute(SESSION_ATTEMPTED, Boolean.TRUE);

        return true;
    }

    private boolean isDue(HttpServletRequest request)
    {
        if (hasCookie(request, LOGGED_OUT_COOKIE_NAME)) {
            return false;
        }

        if (this.configuration.isSilentReauthenticationEnabled() && hasCookie(request, COOKIE_NAME)) {
            return true;
        }

        // Any visitor, as long as the browser sends back cookies: otherwise the provider answer cannot be matched with
        // the session which started the authentication, and the attempt would be repeated for each page (crawlers)
        return this.configuration.isSilentAuthenticationEnabled() && request.getRequestedSessionId() != null;
    }

    /**
     * Redirecting to the provider only makes sense for a page displayed by the browser: the redirect would fail for an
     * AJAX request, and the download of a resource (image, script, etc.) should not consume the single attempt.
     */
    private boolean isPageNavigation(HttpServletRequest request)
    {
        String accept = request.getHeader("Accept");

        return "GET".equals(request.getMethod()) && accept != null && accept.contains("text/html")
            && !"XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }

    private boolean hasCookie(HttpServletRequest request, String name)
    {
        if (request != null && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())) {
                    return true;
                }
            }
        }

        return false;
    }

    private void removeCookie(String name)
    {
        if (hasCookie(getHttpServletRequest(), name)) {
            setCookie(name, "", 0);
        }
    }

    private void setCookie(String name, String value, int maxAge)
    {
        HttpServletRequest request = getHttpServletRequest();
        HttpServletResponse response = getHttpServletResponse();
        if (request != null && response != null) {
            Cookie cookie = new Cookie(name, value);
            cookie.setPath(StringUtils.defaultIfEmpty(request.getContextPath(), "/"));
            cookie.setMaxAge(maxAge);
            cookie.setHttpOnly(true);
            cookie.setSecure(request.isSecure());
            response.addCookie(cookie);
        }
    }

    private HttpServletRequest getHttpServletRequest()
    {
        Request request = this.container.getRequest();

        return request instanceof ServletRequest ? ((ServletRequest) request).getHttpServletRequest() : null;
    }

    private HttpServletResponse getHttpServletResponse()
    {
        Response response = this.container.getResponse();

        return response instanceof ServletResponse ? ((ServletResponse) response).getHttpServletResponse() : null;
    }
}
