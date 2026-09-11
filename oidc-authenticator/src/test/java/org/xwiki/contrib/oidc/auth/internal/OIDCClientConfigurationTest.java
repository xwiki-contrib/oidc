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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.xwiki.configuration.internal.MemoryConfigurationSource;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.endpoint.BackChannelLogoutOIDCEndpoint;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders.ClientProvider;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.usercommon.formatter.UserFormatterFactory;
import org.xwiki.properties.ConverterManager;
import org.xwiki.test.annotation.AfterComponent;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectComponentManager;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.test.mockito.MockitoComponentManager;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;
import com.xpn.xwiki.web.XWikiServletRequestStub;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration.PROP_IS_USED_FOR_AUTHENTICATION;

/**
 * Validate {@link OIDCClientConfiguration}.
 * 
 * @version $Id$
 */
@ComponentTest
@ComponentList(ClientProviders.class)
@ReferenceComponentList
class OIDCClientConfigurationTest
{
    private static final String DISCOVERY_PATH = "/custom/discovery";

    private static final String OTHERISSUER_PATH = "/custom/otherissuer";

    private static final String WELLKNOWN_PATH = "/.well-known/openid-configuration";

    private static final String OTHER_ISSUER = "http://otherissuer";

    /** The deprecated provider property, which is not public in {@link OIDCClientConfiguration}. */
    private static final String PROP_XWIKIPROVIDER = "oidc.xwikiprovider";

    @InjectMockComponents
    private OIDCClientConfiguration configuration;

    @MockComponent
    private Container container;

    @MockComponent
    private OIDCManager manager;

    @MockComponent
    private ConverterManager converterManager;

    @MockComponent
    private OIDCClientConfigurationStore oidcClientConfigurationStore;

    @MockComponent
    private OAuth2TokenStore tokenStore;

    @MockComponent
    private Execution execution;

    @InjectComponentManager
    private MockitoComponentManager componentManager;

    private MemoryConfigurationSource sourceConfiguration;

    private WireMockServer provider;

    private String providerURL;

    @AfterComponent
    void afterComponent() throws Exception
    {
        this.sourceConfiguration = this.componentManager.registerMemoryConfigurationSource();
    }

    @AfterEach
    void afterEach()
    {
        if (this.provider != null) {
            this.provider.stop();
        }
    }

    /**
     * Start a provider exposing a discovery document at the standard location and another one at a custom location, so
     * that the tests can tell which one has been used.
     */
    private void startProvider()
    {
        this.provider = new WireMockServer(options().dynamicPort());
        this.provider.start();
        this.providerURL = "http://localhost:" + this.provider.port();

        // The standard location is exposed by a spec compliant provider, for which the issuer is enough
        this.provider.stubFor(
            get(urlEqualTo(WELLKNOWN_PATH)).willReturn(okJson(metadata("wellknown", this.providerURL).toString())));
        // The custom location is exposed by a provider which cannot be discovered from its issuer
        this.provider.stubFor(
            get(urlEqualTo(DISCOVERY_PATH)).willReturn(okJson(metadata("custom", this.providerURL).toString())));
        // Another custom location, exposing a document which does not indicate the same issuer
        this.provider.stubFor(
            get(urlEqualTo(OTHERISSUER_PATH)).willReturn(okJson(metadata("otherissuer", OTHER_ISSUER).toString())));
    }

    /**
     * Expose a discovery document containing only the mandatory metadata at the passed path.
     */
    private void stubMinimalMetadata(String path)
    {
        JSONObject metadata = new JSONObject();

        metadata.put("issuer", this.providerURL);
        metadata.put("authorization_endpoint", this.providerURL + "/minimal/authorization");
        metadata.put("jwks_uri", this.providerURL + "/minimal/jwks");
        metadata.put("response_types_supported", new JSONArray(List.of("code")));
        metadata.put("subject_types_supported", new JSONArray(List.of("public")));
        metadata.put("id_token_signing_alg_values_supported", new JSONArray(List.of("RS256")));

        this.provider.stubFor(get(urlEqualTo(path)).willReturn(okJson(metadata.toString())));
    }

    /**
     * @param prefix the prefix of the endpoint paths, to identify the discovery document the endpoints are coming from
     * @param issuer the issuer indicated in the metadata
     * @return a minimal but valid OpenID Connect provider metadata
     */
    private JSONObject metadata(String prefix, String issuer)
    {
        JSONObject metadata = new JSONObject();

        metadata.put("issuer", issuer);
        metadata.put("authorization_endpoint", this.providerURL + '/' + prefix + "/authorization");
        metadata.put("token_endpoint", this.providerURL + '/' + prefix + "/token");
        metadata.put("userinfo_endpoint", this.providerURL + '/' + prefix + "/userinfo");
        metadata.put("end_session_endpoint", this.providerURL + '/' + prefix + "/logout");
        metadata.put("jwks_uri", this.providerURL + '/' + prefix + "/jwks");
        metadata.put("response_types_supported", new JSONArray(List.of("code")));
        metadata.put("subject_types_supported", new JSONArray(List.of("public")));
        metadata.put("id_token_signing_alg_values_supported", new JSONArray(List.of("RS256")));

        return metadata;
    }

    private void assertEndPoints(String prefix) throws Exception
    {
        assertEquals(URI.create(this.providerURL + '/' + prefix + "/authorization"),
            this.configuration.getAuthorizationOIDCEndpoint().getURI());
        assertEquals(URI.create(this.providerURL + '/' + prefix + "/token"),
            this.configuration.getTokenOIDCEndpoint().getURI());
        assertEquals(URI.create(this.providerURL + '/' + prefix + "/userinfo"),
            this.configuration.getUserInfoOIDCEndpoint().getURI());
        assertEquals(URI.create(this.providerURL + '/' + prefix + "/logout"),
            this.configuration.getLogoutOIDCEndpoint().getURI());
    }

    private org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration setUpWikiConfig() throws Exception
    {
        String configName = "wiki";
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION_PROPERTY, configName);
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration =
            mock(org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration.class);
        when(this.oidcClientConfigurationStore.getOIDCClientConfiguration(configName)).thenReturn(wikiConfiguration);
        when(this.converterManager.convert(same(String.class), anyString())).thenAnswer(i -> i.getArgument(1));
        when(this.converterManager
            .convert(argThat(type -> type instanceof Class && List.class.isAssignableFrom((Class<?>) type)), anyList()))
                .thenAnswer(i -> i.getArgument(1));
        when(this.converterManager.convert(same(Boolean.class), anyString()))
            .thenAnswer(i -> Boolean.parseBoolean(i.getArgument(1)));
        when(this.converterManager.convert(same(Integer.class), anyInt())).thenAnswer(i -> i.getArgument(1));
        return wikiConfiguration;
    }

    @Test
    void getGroupMappingFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        Map<String, Set<String>> xwikiMapping = new HashMap<>();
        xwikiMapping.put("XWiki.a", Collections.singleton("b"));
        xwikiMapping.put("XWiki.c", Collections.singleton("d"));
        Map<String, Set<String>> providerMapping = new HashMap<>();
        providerMapping.put("b", Collections.singleton("XWiki.a"));
        providerMapping.put("d", Collections.singleton("XWiki.c"));
        List<String> mappingAsString = Arrays.asList("a=b", "XWiki.c=d");
        when(wikiConfiguration.getGroupMapping()).thenReturn(mappingAsString);

        OIDCClientConfiguration.GroupMapping groupMapping = this.configuration.getGroupMapping();
        assertEquals(xwikiMapping, groupMapping.getXWikiMapping());
        assertEquals(providerMapping, groupMapping.getProviderMapping());
    }

    @Test
    void getUserInfoOIDCEndpoint() throws URISyntaxException, GeneralException, IOException
    {
        assertNull(this.configuration.getUserInfoOIDCEndpoint());

        URI uri = new URI("/endpoint");
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, uri.toString());

        Endpoint endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertTrue(endpoint.getHeaders().isEmpty());

        List<String> list = Arrays.asList("key1:value11", "key1:value12", "key2:value2", "alone", ":", "");
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO_HEADERS, list);

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("key1", Arrays.asList("value11", "value12"));
        headers.put("key2", Arrays.asList("value2"));

        endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertEquals(headers, endpoint.getHeaders());
    }

    @Test
    void getUserInfoOIDCEndpointFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        URI uri = new URI("/endpoint");
        when(wikiConfiguration.getUserInfoEndpoint()).thenReturn(uri.toString());
        when(this.converterManager.convert(URI.class, uri.toString())).thenReturn(uri);

        Endpoint endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertTrue(endpoint.getHeaders().isEmpty());

        List<String> list = Arrays.asList("key1:value11", "key1:value12", "key2:value2", "alone", ":", "");
        when(wikiConfiguration.getUserInfoEndpointHeaders()).thenReturn(list);

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("key1", Arrays.asList("value11", "value12"));
        headers.put("key2", Arrays.asList("value2"));
        endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertEquals(headers, endpoint.getHeaders());
    }

    @Test
    void getLogoutEndPointMethod()
    {
        assertEquals(HTTPRequest.Method.GET, this.configuration.getLogoutEndPointMethod());

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_LOGOUT_METHOD,
            HTTPRequest.Method.POST);

        assertEquals(HTTPRequest.Method.POST, this.configuration.getLogoutEndPointMethod());
    }

    @Test
    void getLogoutEndPointMethodFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        // An empty configuration does not count as a set method
        when(wikiConfiguration.getLogoutEndpointMethod()).thenReturn("");

        assertEquals(HTTPRequest.Method.GET, this.configuration.getLogoutEndPointMethod());

        when(wikiConfiguration.getLogoutEndpointMethod()).thenReturn("POST");
        when(this.converterManager.convert(HTTPRequest.Method.class, "POST")).thenReturn(HTTPRequest.Method.POST);

        assertEquals(HTTPRequest.Method.POST, this.configuration.getLogoutEndPointMethod());
    }

    @Test
    void getSubjectFormatterFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        String subjectFormatter = "loremipsum";
        when(wikiConfiguration.getUserSubjectFormatter()).thenReturn(subjectFormatter);

        assertEquals(subjectFormatter, this.configuration.getSubjectFormater());
    }

    @Test
    void getSubjectForbiddenPatternAndReplacementFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        String subjectForbiddenPattern = "\\.";
        when(wikiConfiguration.getUserSubjectForbiddenPattern()).thenReturn(subjectForbiddenPattern);
        assertEquals(subjectForbiddenPattern, this.configuration.getSubjectForbiddenPattern().pattern());

        subjectForbiddenPattern = "";
        when(wikiConfiguration.getUserSubjectForbiddenPattern()).thenReturn(subjectForbiddenPattern);
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_PATTERN, this.configuration.getSubjectForbiddenPattern());

        subjectForbiddenPattern = null;
        when(wikiConfiguration.getUserSubjectForbiddenPattern()).thenReturn(subjectForbiddenPattern);
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_PATTERN, this.configuration.getSubjectForbiddenPattern());

        String subjectForbiddenReplacement = "_";
        when(wikiConfiguration.getUserSubjectForbiddenReplacement()).thenReturn(subjectForbiddenReplacement);
        assertEquals(subjectForbiddenReplacement, this.configuration.getSubjectForbiddenReplacement());

        when(wikiConfiguration.getUserSubjectForbiddenReplacement()).thenReturn("");
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_REPLACEMENT,
            this.configuration.getSubjectForbiddenReplacement());

        when(wikiConfiguration.getUserSubjectForbiddenReplacement()).thenReturn(null);
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_REPLACEMENT,
            this.configuration.getSubjectForbiddenReplacement());
    }

    @Test
    void getXWikiUserNameFormatterFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        String userNameFormatter = "loremipsum";
        when(wikiConfiguration.getUserNameFormatter()).thenReturn(userNameFormatter);

        assertEquals(userNameFormatter, this.configuration.getXWikiUserNameFormater());
    }

    @Test
    void getXWikiUserNameForbiddenPatternAndReplacementFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        String xwikiUsernameForbiddenPattern = "\\.";
        when(wikiConfiguration.getUserNameForbiddenPattern()).thenReturn(xwikiUsernameForbiddenPattern);
        assertEquals(xwikiUsernameForbiddenPattern, this.configuration.getXWikiUserNameForbiddenPattern().pattern());

        xwikiUsernameForbiddenPattern = "";
        when(wikiConfiguration.getUserNameForbiddenPattern()).thenReturn(xwikiUsernameForbiddenPattern);
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_PATTERN,
            this.configuration.getXWikiUserNameForbiddenPattern());

        xwikiUsernameForbiddenPattern = null;
        when(wikiConfiguration.getUserNameForbiddenPattern()).thenReturn(xwikiUsernameForbiddenPattern);
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_PATTERN,
            this.configuration.getXWikiUserNameForbiddenPattern());

        String xwikiUsernameForbiddenReplacement = "_";
        when(wikiConfiguration.getUserNameForbiddenReplacement()).thenReturn(xwikiUsernameForbiddenReplacement);
        assertEquals(xwikiUsernameForbiddenReplacement, this.configuration.getXWikiUserNameForbiddenReplacement());

        when(wikiConfiguration.getUserNameForbiddenReplacement()).thenReturn("");
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_REPLACEMENT,
            this.configuration.getXWikiUserNameForbiddenReplacement());

        when(wikiConfiguration.getUserNameForbiddenReplacement()).thenReturn(null);
        assertEquals(UserFormatterFactory.DEFAULT_FORBIDDEN_REPLACEMENT,
            this.configuration.getXWikiUserNameForbiddenReplacement());
    }

    @Test
    void getUserMappingFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        Map<String, String> mapping = new HashMap<>();
        mapping.put("a", "b");
        mapping.put("c", "d");
        List<String> mappingAsString = Arrays.asList("a=b", "c=d");
        when(wikiConfiguration.getUserMapping()).thenReturn(mappingAsString);

        assertEquals(mapping, this.configuration.getUserMapping());
    }

    @Test
    void getUserInfoRefreshRateFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        Integer refreshRate = 4269;
        when(wikiConfiguration.getUserInfoRefreshRate()).thenReturn(refreshRate);

        assertEquals(refreshRate, this.configuration.getUserInfoRefreshRate());
    }

    @Test
    void getClaimsRequestFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        List<String> idTokenClaims = Arrays.asList("test1", "test2");
        when(wikiConfiguration.getIdTokenClaims()).thenReturn(idTokenClaims);

        List<String> userInfoClaims = Arrays.asList("test3", "test4");
        when(wikiConfiguration.getUserInfoClaims()).thenReturn(userInfoClaims);

        OIDCClaimsRequest claimsRequest = this.configuration.getClaimsRequest();

        // Extract each claim name as ClaimsSetRequest$Entry doesn't implement #equals()
        List<String> foundIdTokenClaims = claimsRequest.getIDTokenClaimsRequest().getEntries().stream()
            .map(e -> e.getClaimName()).collect(Collectors.toList());
        List<String> foundUserInfoClaims = claimsRequest.getUserInfoClaimsRequest().getEntries().stream()
            .map(e -> e.getClaimName()).collect(Collectors.toList());
        assertEquals(idTokenClaims, foundIdTokenClaims);
        assertEquals(userInfoClaims, foundUserInfoClaims);
    }

    @Test
    void getResponseTypeFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        // No response type is set
        assertEquals(ResponseType.CODE, this.configuration.getResponseType());

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_RESPONSE_TYPE, List.of("token"));

        // The response type is set in xwiki.properties
        assertEquals(ResponseType.TOKEN, this.configuration.getResponseType());

        // The wiki configuration is initialized but the response type is still set only in xwiki.properties
        when(wikiConfiguration.getResponseType()).thenReturn(List.of());

        assertEquals(ResponseType.TOKEN, this.configuration.getResponseType());

        // The response type is now set at wiki level and in xwiki.properties
        when(wikiConfiguration.getResponseType()).thenReturn(List.of("id_token", "token"));

        assertEquals(ResponseType.IDTOKEN_TOKEN, this.configuration.getResponseType());
    }

    @Test
    void getClaimsRequestFromWikiConfigJson() throws Exception
    {
        // Using the example string from the OIDCClaimsRequest javadoc
        String userInfoClaimJson = "{\"given_name\":{\"essential\":true},\"nickname\":null,\"email\":"
            + "{\"essential\":true},\"email_verified\":{\"essential\":true},\"picture\":null,"
            + "\"http://example.info/claims/groups\":null}";
        String idTokenClaimJson =
            "{\"auth_time\":{\"essential\":true},\"acr\": {\"values\":[\"urn:mace:incommon:iap:silver\"]}}";
        String claimsJson = "{\"userinfo\":" + userInfoClaimJson + ", \"id_token\":" + idTokenClaimJson + "}";
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_CLAIMS, claimsJson);

        OIDCClaimsRequest claimsRequest = this.configuration.getClaimsRequest();
        ClaimsSetRequest userInfoClaimsRequest = claimsRequest.getUserInfoClaimsRequest();
        ClaimsSetRequest idTokenClaimsRequest = claimsRequest.getIDTokenClaimsRequest();

        assertNotNull(userInfoClaimsRequest.get("given_name"));
        assertEquals(ClaimRequirement.ESSENTIAL, userInfoClaimsRequest.get("given_name").getClaimRequirement());
        assertNotNull(userInfoClaimsRequest.get("nickname"));
        assertNotNull(userInfoClaimsRequest.get("email"));
        assertEquals(ClaimRequirement.ESSENTIAL, userInfoClaimsRequest.get("email").getClaimRequirement());
        assertNotNull(userInfoClaimsRequest.get("email_verified"));
        assertEquals(ClaimRequirement.ESSENTIAL, userInfoClaimsRequest.get("email_verified").getClaimRequirement());
        assertNotNull(userInfoClaimsRequest.get("picture"));
        assertNotNull(userInfoClaimsRequest.get("http://example.info/claims/groups"));

        assertNotNull(idTokenClaimsRequest.get("auth_time"));
        assertEquals(ClaimRequirement.ESSENTIAL, idTokenClaimsRequest.get("auth_time").getClaimRequirement());
        assertNotNull(idTokenClaimsRequest.get("acr"));
        assertEquals(Arrays.asList("urn:mace:incommon:iap:silver"),
            idTokenClaimsRequest.get("acr").getValuesAsListOfStrings());
    }

    @Test
    void getClaimsRequestWithEmptyClaims()
    {
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_IDTOKENCLAIMS, Collections.singletonList(""));
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            Collections.singletonList(""));

        OIDCClaimsRequest claimsRequest = this.configuration.getClaimsRequest();

        assertEquals("{}", claimsRequest.toJSONString());
    }

    @Test
    void getClaimsRequestWithEmptyClaimsJson()
    {
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_IDTOKENCLAIMS,
            Collections.singletonList("idclaim"));
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            Collections.singletonList("userclaim"));
        OIDCClaimsRequest expected = new OIDCClaimsRequest();
        ClaimsSetRequest idtokenclaimsRequest = new ClaimsSetRequest();
        idtokenclaimsRequest = idtokenclaimsRequest.add("idclaim");
        expected = expected.withIDTokenClaimsRequest(idtokenclaimsRequest);
        ClaimsSetRequest userinfoclaimsRequest = new ClaimsSetRequest();
        userinfoclaimsRequest = userinfoclaimsRequest.add("userclaim");
        expected = expected.withUserInfoClaimsRequest(userinfoclaimsRequest);

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_CLAIMS, "");

        OIDCClaimsRequest claimsRequest = this.configuration.getClaimsRequest();

        assertEquals(expected.toJSONObject(), claimsRequest.toJSONObject());
    }

    @Test
    void getGroupClaim()
    {
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");

        assertEquals("groupclaim", this.configuration.getGroupClaim());
    }

    @Test
    void getPropertyWithNullDefaultValue()
    {
        assertNull(this.configuration.getProperty("key", (String) null));

        Request request = mock(Request.class);
        when(request.getProperty(OIDCClientConfiguration.PROP_SKIPPED)).thenReturn("true");
        when(this.container.getRequest()).thenReturn(request);

        assertEquals("true", this.configuration.getProperty(OIDCClientConfiguration.PROP_SKIPPED, (String) null));
    }

    @Test
    void toXWikiGroup()
    {
        assertEquals("XWiki.mygroup", this.configuration.toXWikiGroup("XWiki.mygroup"));
        assertEquals("XWiki.my\\.group", this.configuration.toXWikiGroup("XWiki.my\\.group"));

        assertEquals("XWiki.mygroup", this.configuration.toXWikiGroup("mygroup"));
        assertEquals("XWiki.my\\.group", this.configuration.toXWikiGroup("my.group"));
    }

    @Test
    void expiredToken() throws InterruptedException
    {
        // Ensure we have a Session
        when(execution.getContext()).thenReturn(new ExecutionContext());
        this.configuration.setContextOIDCSession(new HashMap<>());
        this.configuration.setSessionAttribute(PROP_IS_USED_FOR_AUTHENTICATION, true);

        this.configuration.setAccessToken(new BearerAccessToken(), new RefreshToken());
        assertFalse(this.configuration.isAccessTokenExpired(), "an access token without lifetime shouldn't expire");
        this.configuration.setAccessToken(new BearerAccessToken(600L, null), new RefreshToken());
        assertFalse(this.configuration.isAccessTokenExpired(),
            "an access token with a long enough lifetime shouldn't be yet expired");
        this.configuration.setAccessToken(new BearerAccessToken(1L, null), new RefreshToken());
        long now = System.currentTimeMillis();
        Thread.sleep(1100);
        assertTrue(this.configuration.isAccessTokenExpired(),
            "1.1 seconds in the future, an access token valid for one sec expired 0.1 seconds ago");
    }

    @Test
    void getEndPointsWithoutProviderAndDiscoveryEndpoint() throws Exception
    {
        assertNull(this.configuration.getDiscoveryOIDCEndpoint());
        assertNull(this.configuration.getAuthorizationOIDCEndpoint());
        assertNull(this.configuration.getTokenOIDCEndpoint());
        assertNull(this.configuration.getUserInfoOIDCEndpoint());
        assertNull(this.configuration.getLogoutOIDCEndpoint());
        assertNull(this.configuration.getClientProvider());
    }

    @Test
    void getEndPointsFromDiscoveryEndpoint() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);

        assertEquals(URI.create(this.providerURL + DISCOVERY_PATH),
            this.configuration.getDiscoveryOIDCEndpoint().getURI());

        assertEndPoints("custom");

        // The standard location should not be involved at all when the discovery endpoint is configured
        this.provider.verify(0, getRequestedFor(urlEqualTo(WELLKNOWN_PATH)));
    }

    @Test
    void getEndPointsFromDiscoveryEndpointWithoutProvider() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + OTHERISSUER_PATH);

        // There is nothing to compare the issuer indicated by the metadata with, so any issuer is accepted
        assertEndPoints("otherissuer");
        assertEquals(OTHER_ISSUER, this.configuration.getClientProvider().getMetadata().getIssuer().getValue());
    }

    @Test
    void getEndPointsFromDiscoveryEndpointWithUnexpectedIssuer() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_PROVIDER, this.providerURL);
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + OTHERISSUER_PATH);

        // The metadata does not indicate the configured provider as issuer
        GeneralException exception =
            assertThrows(GeneralException.class, () -> this.configuration.getAuthorizationOIDCEndpoint());

        assertEquals("The returned issuer [" + OTHER_ISSUER + "] doesn't match the expected [" + this.providerURL + ']',
            exception.getMessage());
    }

    @Test
    void getEndPointsFromDiscoveryEndpointWithHeaders() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY + ".headers",
            List.of("key1:value1", "key2:value2"));

        assertEndPoints("custom");

        // The configured headers are sent along with the discovery request
        this.provider.verify(getRequestedFor(urlEqualTo(DISCOVERY_PATH)).withHeader("key1", equalTo("value1"))
            .withHeader("key2", equalTo("value2")));
    }

    @Test
    void getEndPointsFromProvider() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_PROVIDER, this.providerURL);

        // No discovery endpoint is configured, it's deduced from the provider
        assertNull(this.configuration.getDiscoveryOIDCEndpoint());

        assertEndPoints("wellknown");

        assertEquals(URI.create(this.providerURL + WELLKNOWN_PATH),
            this.configuration.getClientProvider().getDiscoveryURI());
    }

    @Test
    void getEndPointsFromDiscoveryEndpointWithProvider() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_PROVIDER, this.providerURL);
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);

        // The explicitly configured discovery endpoint wins over the one deduced from the provider
        assertEndPoints("custom");

        this.provider.verify(0, getRequestedFor(urlEqualTo(WELLKNOWN_PATH)));
    }

    @Test
    void getEndPointsFromConfigurationWithDiscoveryEndpoint() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION,
            "http://configured/authorization");

        // An explicitly configured endpoint wins over the one indicated by the discovery document
        assertEquals(URI.create("http://configured/authorization"),
            this.configuration.getAuthorizationOIDCEndpoint().getURI());

        // The other endpoints still come from the discovery document
        assertEquals(URI.create(this.providerURL + "/custom/token"),
            this.configuration.getTokenOIDCEndpoint().getURI());
    }

    @Test
    void getClientProviderIsCachedByDiscoveryEndpoint() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);

        ClientProvider clientProvider = this.configuration.getClientProvider();

        assertNotNull(clientProvider);
        assertEquals(URI.create(this.providerURL + DISCOVERY_PATH), clientProvider.getDiscoveryURI());
        assertEquals(this.providerURL, clientProvider.getMetadata().getIssuer().getValue());

        // The metadata is downloaded only once
        assertSame(clientProvider, this.configuration.getClientProvider());
        assertEndPoints("custom");
        this.provider.verify(1, getRequestedFor(urlEqualTo(DISCOVERY_PATH)));

        // Changing the discovery endpoint leads to a new client provider
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + WELLKNOWN_PATH);

        ClientProvider otherClientProvider = this.configuration.getClientProvider();

        assertNotNull(otherClientProvider);
        assertEquals(URI.create(this.providerURL + WELLKNOWN_PATH), otherClientProvider.getDiscoveryURI());
        assertEquals(this.providerURL, otherClientProvider.getMetadata().getIssuer().getValue());
        assertEndPoints("wellknown");
    }

    @Test
    void getEndPointsWithFailingDiscoveryEndpoint() throws Exception
    {
        startProvider();

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + "/unknown");

        IOException exception =
            assertThrows(IOException.class, () -> this.configuration.getAuthorizationOIDCEndpoint());

        assertEquals("Couldn't download OpenID Provider metadata from " + this.providerURL + "/unknown"
            + ": Status code 404", exception.getMessage());
    }

    @Test
    void getPropertyFromRequest() throws Exception
    {
        XWikiServletRequestStub requestStub = new XWikiServletRequestStub(new URL("http://url"), null);

        when(this.container.getRequest()).thenReturn(new ServletRequest(requestStub));

        assertFalse(this.configuration.isSkipped());
        assertTrue(this.configuration.isTryLocalEnabled());

        requestStub.put(OIDCClientConfiguration.PROP_SKIPPED, "true");
        when(this.converterManager.convert(Boolean.class, "true")).thenReturn(true);

        assertTrue(this.configuration.isSkipped());

        requestStub.put(OIDCClientConfiguration.PROP_GROUPS_ALLOWED, "true");

        assertNull(this.configuration.getAllowedGroups());

        requestStub.put(OIDCClientConfiguration.PROP_PROVIDER, "http://urlprovider");
        requestStub.put(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY, "http://urldiscovery");
        requestStub.put(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION, "http://urlauthorization");

        // Neither the provider nor the endpoints can be injected through the request
        assertNull(this.configuration.getProvider());
        assertNull(this.configuration.getDiscoveryOIDCEndpoint());
        assertNull(this.configuration.getAuthorizationOIDCEndpoint());
        assertNull(this.configuration.getTokenOIDCEndpoint());
    }

    @Test
    void getEndPointsWithEmptyProvider() throws Exception
    {
        startProvider();

        // An empty provider is not a provider
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_PROVIDER, "");
        this.sourceConfiguration.setProperty(PROP_XWIKIPROVIDER, "");

        assertNull(this.configuration.getProvider());
        assertNull(this.configuration.getIssuer());
        assertNull(this.configuration.getClientProvider());
        assertNull(this.configuration.getAuthorizationOIDCEndpoint());

        // The discovery endpoint is still enough to resolve the endpoints
        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);

        assertEndPoints("custom");
    }

    @Test
    void getEndPointsMissingFromMetadata() throws Exception
    {
        startProvider();

        stubMinimalMetadata(DISCOVERY_PATH);

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);

        assertEquals(URI.create(this.providerURL + "/minimal/authorization"),
            this.configuration.getAuthorizationOIDCEndpoint().getURI());

        // The endpoints the metadata does not indicate are simply unknown
        assertNull(this.configuration.getTokenOIDCEndpoint());
        assertNull(this.configuration.getUserInfoOIDCEndpoint());
        assertNull(this.configuration.getLogoutOIDCEndpoint());
    }

    @Test
    void getDiscoveryOIDCEndpointFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        startProvider();

        when(wikiConfiguration.getDiscoveryEndpoint()).thenReturn(this.providerURL + DISCOVERY_PATH);

        assertEquals(URI.create(this.providerURL + DISCOVERY_PATH),
            this.configuration.getDiscoveryOIDCEndpoint().getURI());

        assertEndPoints("custom");
    }

    @Test
    void getClientIDRegisteredThroughDiscoveryEndpoint() throws Exception
    {
        startProvider();

        // The provider indicates a registration endpoint and no client id is configured
        JSONObject metadata = metadata("custom", this.providerURL);
        metadata.put("registration_endpoint", this.providerURL + "/register");
        this.provider.stubFor(get(urlEqualTo(DISCOVERY_PATH)).willReturn(okJson(metadata.toString())));

        JSONObject registration = new JSONObject();
        registration.put("client_id", "registeredclientid");
        this.provider.stubFor(post(urlEqualTo("/register")).willReturn(okJson(registration.toString())));

        this.sourceConfiguration.setProperty(OIDCClientConfiguration.PROP_ENDPOINT_DISCOVERY,
            this.providerURL + DISCOVERY_PATH);
        when(this.manager.createEndPointURI(CallbackOIDCEndpoint.HINT))
            .thenReturn(URI.create("http://xwiki/oidc/authenticator/callback"));
        when(this.manager.createEndPointURI(BackChannelLogoutOIDCEndpoint.HINT))
            .thenReturn(URI.create("http://xwiki/oidc/authenticator/backchannel_logout"));

        assertEquals("registeredclientid", this.configuration.getClientProvider().getClientID().getValue());
        assertEquals("registeredclientid", this.configuration.getClientID().getValue());

        // The client is registered only once
        this.provider.verify(1, postRequestedFor(urlEqualTo("/register")));

        // A configured client id makes the registration useless
        assertNull(this.configuration.getConfiguredClientID());
    }
}
