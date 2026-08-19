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
package org.xwiki.contrib.oidc.auth.internal.endpoint;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.OIDCUserManager;
import org.xwiki.contrib.oidc.auth.internal.session.ClientHttpSessions;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.observation.ObservationManager;
import org.xwiki.properties.ConverterManager;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link CallbackOIDCEndpoint}.
 *
 * @version $Id$
 */
@OldcoreTest
@ComponentList({OIDCClientConfiguration.class, ClientProviders.class})
@ReferenceComponentList
class CallbackOIDCEndpointTest
{
    private static final String CLIENT_ID = "myclientid";

    private static final String SUBJECT = "subject";

    private static final String STATE = "mystate";

    private static final String NONCE = "mynonce";

    private static final String KEY_ID = "mykeyid";

    private static final String OTHER_ISSUER = "http://otherissuer";

    private static final URI SUCCESS_URI = URI.create("http://xwiki/initialrequest");

    @MockComponent
    private Container container;

    @MockComponent
    private OIDCManager oidc;

    @MockComponent
    private OIDCUserManager users;

    @MockComponent
    private ObservationManager observationManager;

    @MockComponent
    @Named("document")
    private UserReferenceResolver<String> userResolver;

    @MockComponent
    private ClientHttpSessions sessions;

    @MockComponent
    private ConverterManager converterManager;

    @MockComponent
    private InstanceIdManager instanceIdManager;

    @MockComponent
    private OIDCClientConfigurationStore oidcClientConfigurationStore;

    @MockComponent
    private OAuth2TokenStore tokenStore;

    @InjectMockComponents
    private CallbackOIDCEndpoint endpoint;

    @InjectMockComponents
    private OIDCClientConfiguration configuration;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private HttpSession httpSession;

    private WireMockServer provider;

    private String issuer;

    private RSAKey jwk;

    @BeforeEach
    void beforeEach() throws Exception
    {
        this.jwk = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();

        this.provider = startProvider();
        this.issuer = "http://localhost:" + this.provider.port();

        initializeSession();

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_PROVIDER, this.issuer);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, CLIENT_ID);

        when(this.oidcClientConfigurationStore.getOIDCClientConfigurationDocument("default")).thenReturn(null);
        when(this.userResolver.resolve(any())).thenReturn(mock(UserReference.class));
        when(this.users.updateUser(any())).thenReturn(new SimplePrincipal("XWiki.user"));
    }

    @AfterEach
    void afterEach()
    {
        this.provider.stop();
    }

    private void initializeSession()
    {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        this.httpSession = mock(HttpSession.class);
        Map<String, Object> session = new HashMap<>();
        when(this.httpSession.getAttribute(OIDCClientConfiguration.SESSION)).thenReturn(session);
        when(httpServletRequest.getSession()).thenReturn(this.httpSession);
        when(httpServletRequest.getSession(true)).thenReturn(this.httpSession);
        ServletSession servletSession = new ServletSession(httpServletRequest);
        when(this.container.getSession()).thenReturn(servletSession);
    }

    /**
     * Start a provider exposing the discovery document and the JWK set used to sign the ID tokens.
     */
    private WireMockServer startProvider()
    {
        WireMockServer wireMockServer = new WireMockServer(options().dynamicPort());
        wireMockServer.start();

        String providerURL = "http://localhost:" + wireMockServer.port();

        JSONObject metadata = new JSONObject();
        metadata.put("issuer", providerURL);
        metadata.put("authorization_endpoint", providerURL + "/authorization");
        metadata.put("token_endpoint", providerURL + "/token");
        metadata.put("jwks_uri", providerURL + "/jwks");
        metadata.put("response_types_supported", new JSONArray(List.of("code", "token", "id_token")));
        metadata.put("subject_types_supported", new JSONArray(List.of("public")));
        metadata.put("id_token_signing_alg_values_supported", new JSONArray(List.of("RS256")));

        wireMockServer.stubFor(
            get(urlEqualTo("/.well-known/openid-configuration")).willReturn(okJson(metadata.toString())));
        wireMockServer
            .stubFor(get(urlEqualTo("/jwks")).willReturn(okJson(new JWKSet(this.jwk.toPublicJWK()).toString())));

        return wireMockServer;
    }

    private JWTClaimsSet.Builder claims()
    {
        long now = System.currentTimeMillis();

        return new JWTClaimsSet.Builder().issuer(this.issuer).subject(SUBJECT).audience(CLIENT_ID)
            .expirationTime(new Date(now + 3600000L)).issueTime(new Date(now)).claim("nonce", NONCE);
    }

    /**
     * @return an ID token signed with the key exposed by the provider JWK set
     */
    private JWT signedIDToken(JWTClaimsSet claims) throws JOSEException
    {
        return signedIDToken(claims, this.jwk);
    }

    private JWT signedIDToken(JWTClaimsSet claims, RSAKey key) throws JOSEException
    {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(), claims);
        jwt.sign(new RSASSASigner(key));

        return jwt;
    }

    /**
     * Simulate a call to the callback endpoint with the passed authorization response parameters.
     */
    private Response callback(String query) throws Exception
    {
        HTTPRequest httpRequest =
            new HTTPRequest(HTTPRequest.Method.GET, URI.create("http://xwiki/oidc/authenticator/callback?" + query));

        return this.endpoint.handle(httpRequest,
            new OIDCResourceReference(CallbackOIDCEndpoint.HINT, CallbackOIDCEndpoint.HINT, List.of()));
    }

    private Response callbackWithIDToken(JWT idToken) throws Exception
    {
        // An access token is sent along with the ID token, as in a standard implicit flow
        return callback("state=" + STATE + "&token_type=Bearer&access_token=myaccesstoken&id_token="
            + idToken.serialize());
    }

    private void assertErrorResponse(int code, String description, Response response)
    {
        HTTPResponse httpResponse = response.toHTTPResponse();

        assertEquals(code, httpResponse.getStatusCode());
        assertEquals(description, httpResponse.getBody());
        assertNotAuthenticated();
    }

    /**
     * Make sure that no user ended up authenticated in the session.
     */
    private void assertNotAuthenticated()
    {
        verify(this.httpSession, never()).setAttribute(eq(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY), any());
    }

    // Tests

    @Test
    void callbackWithoutOIDCSession() throws Exception
    {
        when(this.httpSession.getAttribute(OIDCClientConfiguration.SESSION)).thenReturn(null);

        assertErrorResponse(HTTPResponse.SC_BAD_REQUEST,
            "There is no OpenID Connection information in the current session (anymore?)",
            callback("code=mycode&state=" + STATE));
    }

    @Test
    void callbackWithoutStateInSession() throws Exception
    {
        assertErrorResponse(HTTPResponse.SC_BAD_REQUEST,
            "No state could be found in the current OpenID Connection session"
                + " which suggest it was lost or that this callback endpoint was called directly",
            callback("code=mycode&state=" + STATE));
    }

    @Test
    void callbackWithoutStateInResponse() throws Exception
    {
        this.configuration.setSessionState(STATE);

        assertErrorResponse(HTTPResponse.SC_BAD_REQUEST, "Invalid state: was expecting [" + STATE + "] and got nothing",
            callback("code=mycode"));
    }

    @Test
    void callbackWithWrongState() throws Exception
    {
        this.configuration.setSessionState(STATE);

        assertErrorResponse(HTTPResponse.SC_BAD_REQUEST,
            "Invalid state: was expecting [" + STATE + "] and got [wrongstate]",
            callback("code=mycode&state=wrongstate"));
    }

    /**
     * The RFC 9207 {@code iss} response parameter must match the issuer of the provider the request was sent to.
     */
    @Test
    void callbackWithWrongIssuer() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        assertErrorResponse(HTTPResponse.SC_BAD_REQUEST,
            "Invalid issuer: was expecting [" + this.issuer + "] and got [" + OTHER_ISSUER + "]",
            callback("state=" + STATE + "&iss=" + OTHER_ISSUER + "&token_type=Bearer&access_token=myaccesstoken"
                + "&id_token=" + signedIDToken(claims().build()).serialize()));
    }

    /**
     * An ID token received from the authorization endpoint can only be trusted if it's bound to the nonce generated for
     * the request, so it's ignored when the session does not contain any nonce. Since there is no authorization code to
     * fallback on in that response, no id token is left at all.
     */
    @Test
    void callbackWithIDTokenAndWithoutNonceInSession() throws Exception
    {
        this.configuration.setSessionState(STATE);

        assertErrorResponse(HTTPResponse.SC_BAD_REQUEST, "No id token could be found",
            callbackWithIDToken(signedIDToken(claims().build())));
    }

    /**
     * An unsigned ID token must never be accepted: this is what allows anyone knowing the endpoint to impersonate any
     * user by simply crafting the wanted claims.
     */
    @Test
    void callbackWithUnsignedIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        JWT idToken = new PlainJWT(claims().subject("Admin").build());

        GeneralException exception =
            assertThrows(GeneralException.class, () -> callbackWithIDToken(idToken));
        assertEquals("The OpenID Provider doesn't support null ID tokens", exception.getMessage());
        assertNotAuthenticated();
    }

    /**
     * An ID token signed with a key which is not the one exposed by the provider must be refused.
     */
    @Test
    void callbackWithWrongSignatureIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        // Same key id as the provider one, but a different key
        JWT idToken = signedIDToken(claims().build(), new RSAKeyGenerator(2048).keyID(KEY_ID).generate());

        BadJOSEException exception = assertThrows(BadJOSEException.class, () -> callbackWithIDToken(idToken));
        assertTrue(exception.getMessage().startsWith("Signed JWT rejected:"), exception.getMessage());
        assertNotAuthenticated();
    }

    /**
     * The issuer claim of the ID token is what decides which XWiki user is behind the subject, so it must match the
     * provider the request was sent to.
     */
    @Test
    void callbackWithWrongIssuerIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        JWT idToken = signedIDToken(claims().issuer(OTHER_ISSUER).build());

        BadJOSEException exception = assertThrows(BadJOSEException.class, () -> callbackWithIDToken(idToken));
        assertEquals("Unexpected JWT issuer: " + OTHER_ISSUER, exception.getMessage());
        assertNotAuthenticated();
    }

    /**
     * An ID token produced for another client must be refused.
     */
    @Test
    void callbackWithWrongAudienceIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        JWT idToken = signedIDToken(claims().audience("otherclientid").build());

        BadJOSEException exception = assertThrows(BadJOSEException.class, () -> callbackWithIDToken(idToken));
        assertEquals("Unexpected JWT audience: [otherclientid]", exception.getMessage());
        assertNotAuthenticated();
    }

    @Test
    void callbackWithExpiredIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        JWT idToken = signedIDToken(claims().expirationTime(new Date(System.currentTimeMillis() - 3600000L)).build());

        BadJOSEException exception = assertThrows(BadJOSEException.class, () -> callbackWithIDToken(idToken));
        assertEquals("Expired JWT", exception.getMessage());
        assertNotAuthenticated();
    }

    /**
     * An ID token bound to another nonce than the one of the current session must be refused, otherwise a valid ID
     * token obtained elsewhere could be replayed.
     */
    @Test
    void callbackWithWrongNonceIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);

        JWT idToken = signedIDToken(claims().claim("nonce", "othernonce").build());

        BadJOSEException exception = assertThrows(BadJOSEException.class, () -> callbackWithIDToken(idToken));
        assertEquals("Unexpected JWT nonce (nonce) claim: othernonce", exception.getMessage());
        assertNotAuthenticated();
    }

    @Test
    void callbackWithValidIDToken() throws Exception
    {
        this.configuration.setSessionState(STATE);
        this.configuration.setSessionNonce(NONCE);
        this.configuration.setSuccessRedirectURI(SUCCESS_URI);

        Response response = callbackWithIDToken(signedIDToken(claims().build()));

        assertTrue(response.indicatesSuccess());
        assertEquals(SUCCESS_URI, response.toHTTPResponse().getLocation());

        verify(this.httpSession).setAttribute(eq(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY), any());
    }
}
