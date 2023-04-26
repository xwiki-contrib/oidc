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

import java.net.MalformedURLException;
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

import org.junit.jupiter.api.Test;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.endpoint.TokenOIDCEndpoint;
import org.xwiki.properties.ConverterManager;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.xpn.xwiki.web.XWikiServletRequestStub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCClientConfiguration}.
 * 
 * @version $Id$
 */
@ComponentTest
class OIDCClientConfigurationTest
{
    @InjectMockComponents
    private OIDCClientConfiguration configuration;

    @MockComponent
    private ConfigurationSource sourceConfiguration;

    @MockComponent
    private Container container;

    @MockComponent
    private OIDCManager manager;

    @MockComponent
    private ConverterManager converterManager;

    @MockComponent
    private OIDCClientConfigurationStore oidcClientConfigurationStore;

    private org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration setUpWikiConfig() throws Exception
    {
        String configName = "wiki";
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION_PROPERTY,
            OIDCClientConfiguration.DEFAULT_CLIENT_CONFIGURATION)).thenReturn(configName);
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration =
            mock(org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration.class);
        when(this.oidcClientConfigurationStore.getOIDCClientConfiguration(configName)).thenReturn(wikiConfiguration);

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
        when(this.converterManager.convert(eq(List.class), eq(mappingAsString))).thenReturn(mappingAsString);

        OIDCClientConfiguration.GroupMapping groupMapping = this.configuration.getGroupMapping();
        assertEquals(xwikiMapping, groupMapping.getXWikiMapping());
        assertEquals(providerMapping, groupMapping.getProviderMapping());
    }

    @Test
    void getUserInfoOIDCEndpoint() throws URISyntaxException
    {
        assertNull(this.configuration.getUserInfoOIDCEndpoint());

        URI uri = new URI("/endpoint");
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, String.class))
            .thenReturn(uri.toString());

        Endpoint endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertTrue(endpoint.getHeaders().isEmpty());

        List<String> list = Arrays.asList("key1:value11", "key1:value12", "key2:value2", "alone", ":", "");
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO_HEADERS, List.class))
            .thenReturn(list);

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
        when(this.converterManager.convert(String.class, uri.toString())).thenReturn(uri.toString());
        when(this.converterManager.convert(URI.class, uri.toString())).thenReturn(uri);

        Endpoint endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertTrue(endpoint.getHeaders().isEmpty());

        List<String> list = Arrays.asList("key1:value11", "key1:value12", "key2:value2", "alone", ":", "");
        when(wikiConfiguration.getUserInfoEndpointHeaders()).thenReturn(list);
        when(this.converterManager.convert(eq(List.class), eq(list))).thenReturn(list);

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("key1", Arrays.asList("value11", "value12"));
        headers.put("key2", Arrays.asList("value2"));
        endpoint = this.configuration.getUserInfoOIDCEndpoint();

        assertEquals(uri, endpoint.getURI());
        assertEquals(headers, endpoint.getHeaders());
    }

    @Test
    void getPropertyOrder() throws MalformedURLException, URISyntaxException
    {
        String provider = "http://urlprovider";
        URI urlauthorization = new URI("http://urlauthorization");

        XWikiServletRequestStub requestStub = new XWikiServletRequestStub(new URL("http://url"), null);

        when(this.container.getRequest()).thenReturn(new ServletRequest(requestStub));
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.PROP_SKIPPED, false)).thenReturn(false);

        assertFalse(this.configuration.isSkipped());
        assertNull(this.configuration.getXWikiProvider());
        assertNull(this.configuration.getAuthorizationOIDCEndpoint());
        assertNull(this.configuration.getAuthorizationOIDCEndpoint());
        assertNull(this.configuration.getTokenOIDCEndpoint());

        requestStub.put(OIDCClientConfiguration.PROP_SKIPPED, "true");
        when(this.converterManager.convert(Boolean.class, "true")).thenReturn(true);

        assertTrue(this.configuration.isSkipped());

        requestStub.put(OIDCClientConfiguration.PROP_GROUPS_ALLOWED, "true");

        assertNull(this.configuration.getAllowedGroups());

        requestStub.put(OIDCClientConfiguration.PROP_XWIKIPROVIDER, provider.toString());
        requestStub.put(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION, urlauthorization.toString());
        when(this.manager.createEndPointURI(provider, TokenOIDCEndpoint.HINT)).thenReturn(new URI(provider));

        assertEquals(urlauthorization, this.configuration.getAuthorizationOIDCEndpoint().getURI());
        assertEquals(provider, this.configuration.getTokenOIDCEndpoint().getURI().toString());
    }

    @Test
    void getSubjectFormatterFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        String subjectFormatter = "loremipsum";
        when(wikiConfiguration.getUserSubjectFormatter()).thenReturn(subjectFormatter);
        when(this.converterManager.convert(String.class, subjectFormatter)).thenReturn(subjectFormatter);

        assertEquals(subjectFormatter, this.configuration.getSubjectFormater());
    }

    @Test
    void getXWikiUserNameFormatterFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        String userNameFormatter = "loremipsum";
        when(wikiConfiguration.getUserNameFormatter()).thenReturn(userNameFormatter);
        when(this.converterManager.convert(String.class, userNameFormatter)).thenReturn(userNameFormatter);

        assertEquals(userNameFormatter, this.configuration.getXWikiUserNameFormater());
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
        when(this.converterManager.convert(eq(List.class), eq(mappingAsString))).thenReturn(mappingAsString);

        assertEquals(mapping, this.configuration.getUserMapping());
    }

    @Test
    void getUserInfoRefreshRateFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        Integer refreshRate = 4269;
        when(wikiConfiguration.getUserInfoRefreshRate()).thenReturn(refreshRate);
        when(this.converterManager.convert(Integer.class, refreshRate)).thenReturn(refreshRate);

        assertEquals(refreshRate, this.configuration.getUserInfoRefreshRate());
    }

    @Test
    void getClaimsRequestFromWikiConfig() throws Exception
    {
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiConfiguration = setUpWikiConfig();

        List<String> idTokenClaims = Arrays.asList("test1", "test2");
        when(wikiConfiguration.getIdTokenClaims()).thenReturn(idTokenClaims);
        when(this.converterManager.convert(any(), eq(idTokenClaims))).thenReturn(idTokenClaims);

        List<String> userInfoClaims = Arrays.asList("test3", "test4");
        when(wikiConfiguration.getUserInfoClaims()).thenReturn(userInfoClaims);
        when(this.converterManager.convert(any(), eq(userInfoClaims))).thenReturn(userInfoClaims);

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
    void getClaimsRequestWithEmptyClaims()
    {
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.PROP_IDTOKENCLAIMS,
            OIDCClientConfiguration.DEFAULT_IDTOKENCLAIMS)).thenReturn(Collections.singletonList(""));
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS)).thenReturn(Collections.singletonList(""));

        OIDCClaimsRequest claimsRequest = this.configuration.getClaimsRequest();

        assertEquals("{}", claimsRequest.toJSONString());
    }

    @Test
    void getGroupClaim()
    {
        when(this.sourceConfiguration.getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM,
            OIDCClientConfiguration.DEFAULT_GROUPSCLAIM)).thenReturn("groupclaim");

        assertEquals("groupclaim", this.configuration.getGroupClaim());
    }
}
