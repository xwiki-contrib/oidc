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
package org.xwiki.contrib.oidc.internal;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.context.concurrent.ContextStoreManager;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.auth.store.OIDCClientsConfigurationStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.job.JobExecutor;
import org.xwiki.properties.ConverterManager;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link DefaultOAuth2ClientManager}.
 *
 * @version $Id$
 */
@OldcoreTest
@ComponentList({ OIDCClientConfiguration.class, ClientProviders.class })
@ReferenceComponentList
class DefaultOAuth2ClientManagerTest
{
    private static final String AUTHENTICATION_CONFIGURATION = "authentication";

    private static final String OAUTH2_CONFIGURATION = "oauth2";

    private static final String AUTHENTICATION_ACCESS_TOKEN = "authenticationaccesstoken";

    private static final String AUTHENTICATION_REFRESH_TOKEN = "authenticationrefreshtoken";

    private static final String AUTHENTICATION_ID_TOKEN = "authenticationidtoken";

    private static final String AUTHORIZATION_ENDPOINT = "http://provider/authorization";

    private static final URI CALLBACK_URI = URI.create("http://xwiki/oidc/authenticator/callback");

    private static final URI REDIRECT_URI = URI.create("http://xwiki/afterauthorization");

    @MockComponent
    private Container container;

    @MockComponent
    private OIDCManager oidc;

    @MockComponent
    private ConverterManager converterManager;

    @MockComponent
    private InstanceIdManager instanceIdManager;

    @MockComponent
    private OIDCClientConfigurationStore oidcClientConfigurationStore;

    @MockComponent
    private OIDCClientsConfigurationStore clientsConfigurationStore;

    @MockComponent
    private OAuth2TokenStore tokenStore;

    @MockComponent
    private ContextStoreManager contextStoreManager;

    @MockComponent
    private JobExecutor jobExecutor;

    @InjectMockComponents
    private OIDCClientConfiguration configuration;

    @InjectMockComponents
    private DefaultOAuth2ClientManager manager;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @BeforeEach
    void beforeEach() throws Exception
    {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> attributes = new ConcurrentHashMap<>();
        when(httpSession.getAttribute(any())).then(invocation -> attributes.get(invocation.getArgument(0)));
        doAnswer(invocation -> attributes.put(invocation.getArgument(0), invocation.getArgument(1)))
            .when(httpSession).setAttribute(any(), any());
        when(httpServletRequest.getSession()).thenReturn(httpSession);
        when(httpServletRequest.getSession(anyBoolean())).thenReturn(httpSession);
        ServletSession servletSession = new ServletSession(httpServletRequest);
        when(this.container.getSession()).thenReturn(servletSession);

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION,
            AUTHORIZATION_ENDPOINT);

        when(this.oidc.createEndPointURI(anyString())).thenReturn(CALLBACK_URI);
    }

    /**
     * The OAuth2 authorization of a client configuration can be done by a user authenticated through OpenID Connect,
     * and must not lose the information of that authentication, stored in the same session.
     */
    @Test
    void authorizeWhenAuthenticated() throws Exception
    {
        Map<String, Object> oidcSession = this.configuration.getOIDCSession(true);
        oidcSession.put(OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION_PROPERTY, AUTHENTICATION_CONFIGURATION);
        oidcSession.put(OIDCClientConfiguration.PROP_SESSION_ACCESSTOKEN, AUTHENTICATION_ACCESS_TOKEN);
        oidcSession.put(OIDCClientConfiguration.PROP_SESSION_REFRESHTOKEN, AUTHENTICATION_REFRESH_TOKEN);
        oidcSession.put(OIDCClientConfiguration.PROP_SESSION_IDTOKEN_JWT, AUTHENTICATION_ID_TOKEN);

        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration oauth2Configuration =
            mock(org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration.class);
        when(oauth2Configuration.getConfigurationName()).thenReturn(OAUTH2_CONFIGURATION);
        when(oauth2Configuration.getClientId()).thenReturn("oauth2clientid");
        when(oauth2Configuration.getResponseType()).thenReturn(List.of("code"));

        this.manager.authorize(oauth2Configuration, REDIRECT_URI);

        // The user is sent to the provider
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(this.oidc).redirect(location.capture(), eq(true));
        assertTrue(location.getValue().startsWith(AUTHORIZATION_ENDPOINT + '?'), location.getValue());
        String state = URLUtils.parseParameters(URI.create(location.getValue()).getRawQuery()).get("state").get(0);

        // The authentication information is still in the session, which is the one used by the following requests
        assertSame(oidcSession, this.configuration.getOIDCSession(false));
        assertEquals(AUTHENTICATION_CONFIGURATION,
            oidcSession.get(OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION_PROPERTY));
        assertEquals(AUTHENTICATION_ACCESS_TOKEN, oidcSession.get(OIDCClientConfiguration.PROP_SESSION_ACCESSTOKEN));
        assertEquals(AUTHENTICATION_REFRESH_TOKEN,
            oidcSession.get(OIDCClientConfiguration.PROP_SESSION_REFRESHTOKEN));
        assertEquals(AUTHENTICATION_ID_TOKEN, oidcSession.get(OIDCClientConfiguration.PROP_SESSION_IDTOKEN_JWT));
        assertNull(oidcSession.get(OIDCClientConfiguration.PROP_IS_USED_FOR_AUTHENTICATION));
        assertNull(oidcSession.get(OIDCClientConfiguration.PROP_STATE));

        // The OAuth2 authorization is remembered for the callback, without anything coming from the authentication
        Map<String, Object> authorization = this.configuration.removePendingAuthorization(state);
        assertNotNull(authorization);
        assertEquals(state, authorization.get(OIDCClientConfiguration.PROP_STATE));
        assertEquals(OAUTH2_CONFIGURATION,
            authorization.get(OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION_PROPERTY));
        assertEquals(false, authorization.get(OIDCClientConfiguration.PROP_IS_USED_FOR_AUTHENTICATION));
        assertEquals(REDIRECT_URI, authorization.get(OIDCClientConfiguration.PROP_INITIAL_REQUEST));
        assertNull(authorization.get(OIDCClientConfiguration.PROP_SESSION_ACCESSTOKEN));
    }
}
