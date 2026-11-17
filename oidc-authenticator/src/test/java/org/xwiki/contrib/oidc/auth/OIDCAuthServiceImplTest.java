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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.auth.internal.OIDCAuthService;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.user.api.XWikiUser;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCAuthServiceImpl}.
 *
 * @version $Id$
 */
@OldcoreTest
class OIDCAuthServiceImplTest
{
    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private XWikiContext xcontext;

    private OIDCAuthServiceImpl authService;

    @BeforeEach
    void beforeEach()
    {
        this.xcontext = this.oldcore.getXWikiContext();

        this.authService = new OIDCAuthServiceImpl();
    }

    private XWikiAuthServiceComponent registerOIDCAuthService() throws Exception
    {
        return this.oldcore.getMocker().registerMockComponent(XWikiAuthServiceComponent.class, OIDCAuthService.ID);
    }

    @Test
    void checkAuthWithReloadedComponent() throws Exception
    {
        XWikiAuthServiceComponent component = registerOIDCAuthService();
        XWikiUser user = mock(XWikiUser.class);
        when(component.checkAuth(this.xcontext)).thenReturn(user);

        assertSame(user, this.authService.checkAuth(this.xcontext));

        // The component is registered again (for example when the extension is reloaded): the same authenticator
        // instance must use the new component
        XWikiAuthServiceComponent newComponent = registerOIDCAuthService();
        XWikiUser newUser = mock(XWikiUser.class);
        when(newComponent.checkAuth(this.xcontext)).thenReturn(newUser);

        assertSame(newUser, this.authService.checkAuth(this.xcontext));
    }

    @Test
    void checkAuthWithCredentials() throws Exception
    {
        XWikiAuthServiceComponent component = registerOIDCAuthService();
        XWikiUser user = mock(XWikiUser.class);
        when(component.checkAuth("user", "password", "rememberme", this.xcontext)).thenReturn(user);

        assertSame(user, this.authService.checkAuth("user", "password", "rememberme", this.xcontext));
    }

    @Test
    void authenticate() throws Exception
    {
        XWikiAuthServiceComponent component = registerOIDCAuthService();
        Principal principal = mock(Principal.class);
        when(component.authenticate("user", "password", this.xcontext)).thenReturn(principal);

        assertSame(principal, this.authService.authenticate("user", "password", this.xcontext));
    }

    @Test
    void showLogin() throws Exception
    {
        XWikiAuthServiceComponent component = registerOIDCAuthService();

        this.authService.showLogin(this.xcontext);

        verify(component).showLogin(this.xcontext);
    }
}
