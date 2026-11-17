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
package org.xwiki.contrib.oidc.auth;

import java.security.Principal;

import org.xwiki.contrib.oidc.auth.internal.OIDCAuthService;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.web.Utils;

/**
 * Authenticate user trough an OpenID Connect provider.
 * <p>
 * This is the class to set in the {@code xwiki.authentication.authclass} property of {@code xwiki.cfg}. XWiki keeps
 * the same instance until the class itself changes, so this class does not hold anything: each call is forwarded to
 * the {@link OIDCAuthService} component currently registered, which makes sure the authenticator keeps working with
 * up to date components when they are reloaded (for example when the extension, or one of its dependencies, is
 * reloaded by the Extension Manager).
 *
 * @version $Id$
 */
public class OIDCAuthServiceImpl implements XWikiAuthService
{
    private XWikiAuthService getAuthService()
    {
        return Utils.getComponent(XWikiAuthServiceComponent.class, OIDCAuthService.ID);
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        return getAuthService().checkAuth(context);
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        return getAuthService().checkAuth(username, password, rememberme, context);
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        getAuthService().showLogin(context);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        return getAuthService().authenticate(username, password, context);
    }
}
