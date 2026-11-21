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
import java.util.concurrent.locks.ReentrantLock;

import javax.inject.Provider;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.securityfilter.authenticator.persistent.PersistentLoginManagerInterface;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.filter.URLPatternMatcher;
import org.xwiki.component.util.DefaultParameterizedType;
import org.xwiki.container.servlet.filters.SavedRequestManager;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.properties.ConverterManager;
import org.xwiki.script.ScriptContextManager;
import org.xwiki.test.annotation.AfterComponent;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;
import com.xpn.xwiki.user.impl.xwiki.MyFormAuthenticator;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthenticator;
import com.xpn.xwiki.web.XWikiRequest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCAuthService}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCAuthServiceTest
{
    private static final String CLIENT_ID = "myclientid";

    @MockComponent
    private OIDCManager manager;

    @MockComponent
    private OIDCClientConfiguration configuration;

    @MockComponent
    private OIDCUserManager users;

    @MockComponent
    private ConverterManager converter;

    @MockComponent
    private ScriptContextManager scriptContextManager;

    @MockComponent
    private OIDCSilentReauthentication silentReauthentication;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private PersistentLoginManagerInterface persistentLoginManager;

    @InjectMockComponents
    private OIDCAuthService authService;

    @AfterComponent
    void afterComponent() throws Exception
    {
        this.persistentLoginManager = mock(PersistentLoginManagerInterface.class);
        Provider<PersistentLoginManagerInterface> persistentLoginManagerProvider = () -> this.persistentLoginManager;
        this.oldcore.getMocker().registerComponent(
            new DefaultParameterizedType(null, Provider.class, PersistentLoginManagerInterface.class),
            persistentLoginManagerProvider);
    }

    @BeforeEach
    void beforeEach() throws Exception
    {
        doReturn("/bin/view/Main/WebHome").when(this.oldcore.getSpyXWiki())
            .Param("xwiki.authentication.defaultpage");
        doReturn("/bin/login/XWiki/XWikiLogin").when(this.oldcore.getSpyXWiki())
            .Param("xwiki.authentication.loginpage");
        doReturn("/bin/logout/XWiki/XWikiLogout").when(this.oldcore.getSpyXWiki())
            .Param("xwiki.authentication.logoutpage");
        doReturn("/bin/loginerror/XWiki/XWikiLogin").when(this.oldcore.getSpyXWiki())
            .Param("xwiki.authentication.errorpage");

    }

    private SecurityRequestWrapper request(String path)
    {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn("/xwiki");
        when(request.getRequestURI()).thenReturn("/xwiki" + path);
        when(request.getServletPath()).thenReturn("/bin");
        when(request.getPathInfo()).thenReturn(path.substring("/bin".length()));

        return new SecurityRequestWrapper(request, null, null, "FORM");
    }

    @Test
    void getAuthenticatorWithTryLocal() throws Exception
    {
        when(this.configuration.isTryLocalEnabled()).thenReturn(true);

        XWikiAuthenticator authenticator = this.authService.getAuthenticator(this.oldcore.getXWikiContext());

        assertInstanceOf(MyFormAuthenticator.class, authenticator);
        assertSame(authenticator, this.authService.getAuthenticator(this.oldcore.getXWikiContext()));
    }

    @Test
    void getAuthenticatorWithoutTryLocal() throws Exception
    {
        when(this.configuration.isTryLocalEnabled()).thenReturn(false);

        XWikiAuthenticator authenticator = this.authService.getAuthenticator(this.oldcore.getXWikiContext());

        assertInstanceOf(OIDCAuthenticator.class, authenticator);
        assertSame(authenticator, this.authService.getAuthenticator(this.oldcore.getXWikiContext()));

        HttpServletResponse response = mock(HttpServletResponse.class);

        // The standard authentication is disabled
        assertFalse(authenticator.processLogin(request("/bin/view/Main/WebHome"), response,
            this.oldcore.getXWikiContext()));

        // The logout is detected
        assertFalse(authenticator.processLogout(request("/bin/view/Main/WebHome"), response,
            new URLPatternMatcher()));
        SecurityRequestWrapper logoutRequest = request("/bin/logout/XWiki/XWikiLogout");
        assertTrue(authenticator.processLogout(logoutRequest, response, new URLPatternMatcher()));
        verify(this.persistentLoginManager).forgetLogin(logoutRequest, response);
    }

    /**
     * Simulate a request without any user in the session, for the passed action, and return the URL the user is
     * redirected to, if any.
     */
    private String checkAuth(String action) throws Exception
    {
        XWikiRequest request = mock(XWikiRequest.class);
        // No standard authentication, so that the OpenID Connect one is tried
        when(request.getHttpServletRequest()).thenReturn(null);
        when(request.getParameter(SavedRequestManager.getSavedRequestIdentifier())).thenReturn("mysrid");
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("xwiki");
        when(request.getServerPort()).thenReturn(80);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://xwiki/xwiki/bin/view/Main/WebHome"));
        when(request.getRequestURI()).thenReturn("/xwiki/bin/view/Main/WebHome");
        XWikiContext xcontext = this.oldcore.getXWikiContext();
        xcontext.setRequest(request);
        xcontext.setAction(action);

        when(this.configuration.getSessionLock()).thenReturn(new ReentrantLock());
        when(this.configuration.getAuthorizationOIDCEndpoint())
            .thenReturn(new Endpoint(URI.create("http://provider/authorize"), null));
        when(this.configuration.getResponseType()).thenReturn(ResponseType.CODE);
        when(this.configuration.getScope()).thenReturn(new Scope("openid"));
        when(this.configuration.getClientID()).thenReturn(new ClientID(CLIENT_ID));
        when(this.manager.createEndPointURI(CallbackOIDCEndpoint.HINT))
            .thenReturn(URI.create("http://xwiki/xwiki/oidc/authenticator/callback"));

        assertNull(this.authService.checkAuth(xcontext));

        ArgumentCaptor<String> redirect = ArgumentCaptor.forClass(String.class);
        verify(this.manager, atMost(1)).redirect(redirect.capture(), eq(true));

        return redirect.getAllValues().isEmpty() ? null : redirect.getValue();
    }

    @Test
    void checkAuthStartsSilentAuthentication() throws Exception
    {
        when(this.silentReauthentication.startAttempt()).thenReturn(true);

        String redirect = checkAuth("view");

        assertTrue(redirect.startsWith("http://provider/authorize?"), redirect);
        assertTrue(redirect.contains("prompt=none"), redirect);
        assertTrue(redirect.contains("client_id=" + CLIENT_ID), redirect);
    }

    @Test
    void checkAuthWithoutSilentAuthentication() throws Exception
    {
        when(this.silentReauthentication.startAttempt()).thenReturn(false);

        assertNull(checkAuth("view"));
    }

    @Test
    void checkAuthJustAfterLogout() throws Exception
    {
        when(this.configuration.getAccessToken()).thenReturn(new BearerAccessToken());
        when(this.silentReauthentication.startAttempt()).thenReturn(true);

        assertNull(checkAuth("view"));

        verify(this.users).logout();
        verify(this.silentReauthentication, never()).startAttempt();
    }

    @Test
    void checkAuthWithLoginAction() throws Exception
    {
        String redirect = checkAuth("login");

        assertTrue(redirect.startsWith("http://provider/authorize?"), redirect);
        assertFalse(redirect.contains("prompt="), redirect);
        verify(this.silentReauthentication, never()).startAttempt();
    }

    @Test
    void getAuthenticatorPerWiki() throws Exception
    {
        when(this.configuration.isTryLocalEnabled()).thenReturn(false);

        XWikiAuthenticator authenticator = this.authService.getAuthenticator(this.oldcore.getXWikiContext());

        this.oldcore.getXWikiContext().setWikiId("otherwiki");

        assertNotSame(authenticator, this.authService.getAuthenticator(this.oldcore.getXWikiContext()));
    }
}
