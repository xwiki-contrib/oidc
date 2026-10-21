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

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.securityfilter.config.SecurityConfig;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.filter.URLPatternMatcher;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthenticator;

/**
 * Wrap the standard authenticator to disable any standard authentication (form, cookies, basic auth) while keeping
 * everything else (login page, logout handling, etc.).
 * 
 * @version $Id$
 * @since 2.24.0
 */
public class OIDCAuthenticator implements XWikiAuthenticator
{
    private final XWikiAuthenticator standard;

    /**
     * @param standard the standard authenticator, initialized by XWiki with the login, logout and error pages
     *     configuration
     * @since 2.29.1
     */
    public OIDCAuthenticator(XWikiAuthenticator standard)
    {
        this.standard = standard;
    }

    @Override
    public void init(FilterConfig filterConfig, SecurityConfig securityConfig) throws Exception
    {
        this.standard.init(filterConfig, securityConfig);
    }

    @Override
    public String getAuthMethod()
    {
        return this.standard.getAuthMethod();
    }

    @Override
    public void showLogin(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        this.standard.showLogin(request, response);
    }

    @Override
    public void showLogin(HttpServletRequest request, HttpServletResponse response, XWikiContext context)
        throws IOException
    {
        // Skip the BASIC auth checked done by MyFormAuthenticator
        showLogin(request, response);
    }

    @Override
    public boolean processLogin(SecurityRequestWrapper request, HttpServletResponse response) throws Exception
    {
        return processLogin(request, response, null);
    }

    @Override
    public boolean processLogin(SecurityRequestWrapper request, HttpServletResponse response, XWikiContext context)
        throws Exception
    {
        // TODO: non interactive OIDC authentication if we have enough information for it but remember in the session
        // that it failed to not try again
        return false;
    }

    @Override
    public boolean processLogin(String username, String password, String rememberme, SecurityRequestWrapper request,
        HttpServletResponse response, XWikiContext context) throws Exception
    {
        return this.standard.processLogin(username, password, rememberme, request, response, context);
    }

    @Override
    public boolean processLogout(SecurityRequestWrapper request, HttpServletResponse response,
        URLPatternMatcher patternMatcher) throws Exception
    {
        // Rely on the standard authenticator to detect the logout, which is then propagated to the OIDC provider by
        // OIDCAuthServiceImpl
        return this.standard.processLogout(request, response, patternMatcher);
    }

    @Override
    public boolean bypassSecurityForThisRequest(SecurityRequestWrapper request, URLPatternMatcher patternMatcher)
        throws Exception
    {
        return this.standard.bypassSecurityForThisRequest(request, patternMatcher);
    }
}
