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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.inject.Named;
import javax.script.ScriptContext;
import javax.script.SimpleBindings;
import javax.script.SimpleScriptContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections4.ListUtils;
import org.joda.time.LocalDateTime;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration.LogoutMethod;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders;
import org.xwiki.contrib.oidc.auth.internal.store.DefaultOIDCUserStore;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserClassDocumentInitializer;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.auth.store.OIDCClientsConfigurationStore;
import org.xwiki.contrib.oidc.auth.store.OIDCUser;
import org.xwiki.contrib.oidc.consent.internal.OIDCConsentConfiguration;
import org.xwiki.contrib.oidc.consent.internal.store.OIDCConsentStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderException;
import org.xwiki.contrib.oidc.provider.internal.session.OIDCClients;
import org.xwiki.contrib.oidc.provider.internal.session.ProviderOIDCSessions;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCProviderStore;
import org.xwiki.contrib.usercommon.formatter.internal.DefaultUserFormatterFactory;
import org.xwiki.environment.Environment;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.localization.ContextualLocalizationManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.properties.ConverterManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.script.ScriptContextManager;
import org.xwiki.security.authorization.AuthorExecutor;
import org.xwiki.template.TemplateManager;
import org.xwiki.test.LogLevel;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.MandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;
import com.xpn.xwiki.web.XWikiResponse;
import com.xpn.xwiki.web.XWikiServletRequestStub;
import com.xpn.xwiki.web.XWikiURLFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCUserManager}.
 *
 * @version $Id$
 */
@OldcoreTest
@ComponentList({ OIDCManager.class, OIDCClientConfiguration.class, OIDCIdTokenValidator.class,
    DefaultOIDCUserStore.class, OIDCProviderConfiguration.class, OIDCProviderStore.class,
    OIDCConsentConfiguration.class, OIDCConsentStore.class, ProviderOIDCSessions.class, OIDCClients.class,
    ClientProviders.class, DefaultUserFormatterFactory.class })
@ReferenceComponentList
class OIDCUserManagerTest
{
    private static final String CLIENT_ID = "clientid";

    private static final String CLIENT_SECRET = "clientsecret";

    private static final String PROVIDER = "http://provider";

    private static final String LOGOUT_ENDPOINT = "http://provider/logout";

    private static final String AFTER_LOGOUT_URL = "http://wiki/afterlogout";

    private static final String LOGOUT_TEMPLATE = "oidc/client/logout.vm";

    private static final String LOGOUT_FORM = "<form/>";

    private static final String NOT_ROTATED_REFRESH_TOKEN = "notrotatedrefreshtoken";

    // A refresh token the fake provider token endpoint rejects with a standard OAuth2 error
    private static final String EXPIRED_REFRESH_TOKEN = "expiredrefreshtoken";

    // A refresh token the fake provider token endpoint rejects with a response which is not an OAuth2 error
    private static final String REJECTED_REFRESH_TOKEN = "rejectedrefreshtoken";

    private static final String KEY_ID = "providerkey";

    /**
     * When the user authenticated on the fake provider, a few minutes ago.
     */
    private static final long AUTHENTICATION_TIME = System.currentTimeMillis() - 600000L;

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    /**
     * The Authorization headers received by the fake provider token endpoint ("null" when there is none).
     */
    private final List<String> tokenRequestAuthorizations = new ArrayList<>();

    /**
     * The parameters received in the body of the requests to the fake provider token endpoint.
     */
    private final List<Map<String, String>> tokenRequestParameters = new ArrayList<>();

    @MockComponent
    QueryManager queryManager;

    @MockComponent
    InstanceIdManager instanceIdManager;

    @MockComponent
    TemplateManager templateManager;

    @MockComponent
    Environment environment;

    @MockComponent
    AuthorExecutor authorExecutor;

    @MockComponent
    Container container;

    @MockComponent
    ConverterManager converterManager;

    @MockComponent
    OIDCClientConfigurationStore oidcClientConfigurationStore;

    @MockComponent
    @Named("XWiki.XWikiRights")
    MandatoryDocumentInitializer rightsInitializer;

    @MockComponent
    ContextualLocalizationManager contextualLocalizationManager;

    @MockComponent
    ScriptContextManager scriptContextManager;

    @InjectMockComponents
    OIDCUserClassDocumentInitializer classInitializer;

    @InjectMockComponents
    OIDCUserManager manager;

    @InjectMockitoOldcore
    MockitoOldcore oldcore;

    @MockComponent
    OAuth2TokenStore tokenStore;

    @MockComponent
    OIDCClientsConfigurationStore clientsConfigurationStore;

    @InjectMockComponents
    @Spy
    OIDCClientConfiguration configuration;

    private final PlainJWT idToken = new PlainJWT(new JWTClaimsSet.Builder().subject("subject").build());

    /**
     * The key used by the fake provider to sign the ID tokens.
     */
    private RSAKey providerKey;

    /**
     * The ID token the fake provider token endpoint sends with the refreshed access token, if any.
     */
    private JWT refreshedIdToken;

    private DocumentReference xwikiallgroupReference;

    private DocumentReference oidcClassReference;

    private DocumentReference group1Reference;

    private DocumentReference group2Reference;

    private DocumentReference existinggroupReference;

    private DocumentReference pgroup1Reference;

    private DocumentReference pgroup2Reference;

    @BeforeEach
    void beforeEach() throws Exception
    {
        when(queryManager.createQuery(Mockito.anyString(), Mockito.anyString())).thenReturn(mock(Query.class));

        this.xwikiallgroupReference = new DocumentReference("xwiki", "XWiki", "XWikiAllGroup");

        this.oidcClassReference =
            new DocumentReference(OIDCUser.CLASS_REFERENCE, this.oldcore.getXWikiContext().getWikiReference());
        XWikiDocument classDocument =
            this.oldcore.getSpyXWiki().getDocument(this.oidcClassReference, this.oldcore.getXWikiContext());
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, this.oldcore.getXWikiContext());

        this.group1Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "group1");
        this.group2Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "group2");
        this.existinggroupReference =
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "existinggroup");
        this.pgroup1Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "pgroup1");
        this.pgroup2Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "pgroup2");

        when(oidcClientConfigurationStore.getOIDCClientConfigurationDocument("default")).thenReturn(null);

        initializeSessionForOIDCClientConfiguration();
        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        configuration.setAccessToken(new BearerAccessToken(), new RefreshToken());
        configuration.setIdToken(createIDTokenClaimsSet(issuer, subject));
    }

    private void initializeSessionForOIDCClientConfiguration()
    {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        HttpSession httpSession = mock(HttpSession.class);
        HashMap<String, String> session = new HashMap<>();
        when(httpSession.getAttribute(OIDCClientConfiguration.SESSION)).thenReturn(session);
        when(httpServletRequest.getSession()).thenReturn(httpSession);
        when(httpServletRequest.getSession(true)).thenReturn(httpSession);
        ServletSession servletSession = new ServletSession(httpServletRequest);
        when(container.getSession()).thenReturn(servletSession);
        when(container.getSession()).thenReturn(servletSession);
    }

    private void addMember(DocumentReference group, String member) throws XWikiException
    {
        XWikiDocument groupDocument = this.oldcore.getSpyXWiki().getDocument(group, this.oldcore.getXWikiContext());

        if (!groupContains(groupDocument, member)) {
            BaseObject memberObject = groupDocument.newXObject(
                new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiGroups"),
                this.oldcore.getXWikiContext());

            memberObject.setStringValue("member", member);

            this.oldcore.getSpyXWiki().saveDocument(groupDocument, this.oldcore.getXWikiContext());
        }
    }

    private boolean groupContains(DocumentReference group, String member) throws XWikiException
    {
        XWikiDocument groupDocument = this.oldcore.getSpyXWiki().getDocument(group, this.oldcore.getXWikiContext());

        return groupContains(groupDocument, member);
    }

    private boolean groupContains(XWikiDocument groupDocument, String member)
    {
        List<BaseObject> groupObjects = groupDocument
            .getXObjects(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiGroups"));

        if (groupObjects != null) {
            for (BaseObject groupObject : groupObjects) {
                if (groupObject != null && groupObject.getStringValue("member").equals(member)) {
                    return true;
                }
            }
        }

        return false;
    }

    private IDTokenClaimsSet createIDTokenClaimsSet(Issuer issuer, Subject subject)
    {
        LocalDateTime iat = LocalDateTime.now();
        LocalDateTime exp = iat.plusYears(1);

        return new IDTokenClaimsSet(issuer, subject, Audience.create("aud"), exp.toDate(), iat.toDate());
    }

    // Tests

    @Test
    void updateUserInfo()
        throws XWikiException, QueryException, OIDCProviderException, URISyntaxException, MalformedURLException
    {
        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        Address address = new Address();
        address.setFormatted("address");
        userInfo.setPreferredUsername("preferredUserName");
        userInfo.setAddress(address);
        userInfo.setEmailAddress("mail@domain.com");
        userInfo.setFamilyName("familyName");
        userInfo.setGivenName("givenName");
        userInfo.setPhoneNumber("phoneNumber");
        userInfo.setLocale("fr");
        userInfo.setZoneinfo("timezone");
        userInfo.setWebsite(new URI("http://website"));

        Map<String, Object> customClaim = new HashMap<>();
        customClaim.put("customproperty1", "value");
        customClaim.put("customproperty2", 42);
        customClaim.put("customproperty3", null);
        userInfo.setClaim("custom", customClaim);

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_MAPPING,
            Arrays.asList("customproperty1=${oidc.user.custom.customproperty1:-}",
                "customproperty2=${oidc.user.custom.customproperty2:-}",
                "customproperty3=${oidc.user.custom.customproperty3:-}",
                "customproperty4=${oidc.user.custom.customproperty4:-}", "customproperty5=${notexistingpattern}"));

        // Add custom fields to the class
        BaseClass userClass = this.oldcore.getSpyXWiki().getUserClass(this.oldcore.getXWikiContext());
        userClass.addTextField("customproperty1", "customproperty1", 30);
        userClass.addNumberField("customproperty2", "customproperty2", 30, "integer");
        userClass.addTextField("customproperty3", "customproperty3", 30);
        userClass.addTextField("customproperty4", "customproperty4", 30);
        userClass.addTextField("customproperty5", "customproperty5", 30);
        XWikiDocument userClassDocument =
            this.oldcore.getSpyXWiki().getDocument(userClass.getDocumentReference(), this.oldcore.getXWikiContext());
        userClassDocument.getXClass().apply(userClass, true);
        this.oldcore.getSpyXWiki().saveDocument(userClassDocument, this.oldcore.getXWikiContext());

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-preferredUserName", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-preferredUserName"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument.getXObject(userClass.getDocumentReference());

        assertNotNull(userObject);
        assertEquals("address", userObject.getStringValue("address"));
        assertEquals("mail@domain.com", userObject.getStringValue("email"));
        assertEquals("familyName", userObject.getStringValue("last_name"));
        assertEquals("givenName", userObject.getStringValue("first_name"));
        assertEquals("phoneNumber", userObject.getStringValue("phone"));
        assertEquals("value", userObject.getStringValue("customproperty1"));
        assertEquals(42, userObject.getIntValue("customproperty2"));
        assertEquals("", userObject.getStringValue("customproperty3"));
        assertEquals("", userObject.getStringValue("customproperty4"));
        assertEquals("", userObject.getStringValue("customproperty5"));

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());
    }

    @Test
    void updateUserInfoWithGroupSyncWithDefaultGroupsClaim()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS,
                Arrays.asList(OIDCClientConfiguration.DEFAULT_GROUPSCLAIM)));

        userInfo.setClaim(OIDCClientConfiguration.DEFAULT_GROUPSCLAIM, Arrays.asList("pgroup1", "pgroup2"));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        assertTrue(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.pgroup2Reference, userDocument.getFullName()));
    }

    @Test
    void updateUserInfoWithGroupSyncWithoutMapping()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, userFullName);
        addMember(this.xwikiallgroupReference, userFullName);

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        assertTrue(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.pgroup2Reference, userDocument.getFullName()));
        assertFalse(groupContains(this.existinggroupReference, userDocument.getFullName()));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));
    }

    @Test
    void updateUserInfoWithGroupSyncWithoutMappingAndIncludeRegex()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_INCLUDE,
            "^XWiki\\.[A-Za-z]*group[A-Za-z]*1$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, userFullName);
        addMember(this.xwikiallgroupReference, userFullName);

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        // we're expecting: user stays in initial group, gets synced in the first group, doesn't get synced in the
        // second group and doesn't get removed from existing group, because existing group doesn't match the mapping
        // regex
        assertTrue(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        assertFalse(groupContains(this.pgroup2Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.existinggroupReference, userDocument.getFullName()));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));
    }

    @Test
    void updateUserInfoWithGroupSyncWithoutMappingAndExcludeRegex()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_EXCLUDE,
            "^XWiki\\.[A-Za-z]*group[A-Za-z]*1$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, userFullName);
        addMember(this.xwikiallgroupReference, userFullName);

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        // we're expecting: user stays in initial group, gets synced out of the first group, gets synced in the
        // second group and doesn't get removed from existing group, because existing group doesn't match the mapping
        // exclusion, so it's included
        assertFalse(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.pgroup2Reference, userDocument.getFullName()));
        assertFalse(groupContains(this.existinggroupReference, userDocument.getFullName()));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));
    }

    @Test
    void updateUserInfoWithGroupSyncWithoutMappingAndIncludeExcludeRegex()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_INCLUDE,
            "^.*pgroup.*$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_EXCLUDE, ".*2$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, userFullName);
        addMember(this.xwikiallgroupReference, userFullName);

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        // we're expecting: user stays in initial group, gets synced in the first group, does not get synced in the
        // second group and doesn't get removed from existing group, because existing group doesn't match the inclusion,
        // so it's not updated included
        assertTrue(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        assertFalse(groupContains(this.pgroup2Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.existinggroupReference, userDocument.getFullName()));
        assertTrue(groupContains(this.xwikiallgroupReference, userFullName));
    }

    @Test
    void updateUserInfoWithGroupSyncWithExplicitMappingIgnoresRegex()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING,
            Arrays.asList("group1=pgroup1", "group1=pgroup2", "XWiki.group2=pgroup2", "existinggroup=othergroup"));
        // it doesn't matter that these are including and excluding the same group, we're testing that they are ignored
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_INCLUDE, "\\d+");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_EXCLUDE, "\\d+");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, "XWiki.issuer-subject");

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        assertTrue(groupContains(this.group1Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.group2Reference, userDocument.getFullName()));
        assertFalse(groupContains(this.existinggroupReference, userDocument.getFullName()));

        assertEquals("User [XWiki.issuer-subject] already exist in group [xwiki:XWiki.group1]",
            this.logCapture.getMessage(0));
    }

    @Test
    void updateUserInfoWithGroupSyncWithMapping()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING,
            Arrays.asList("group1=pgroup1", "group1=pgroup2", "XWiki.group2=pgroup2", "existinggroup=othergroup"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, "XWiki.issuer-subject");

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("subject", oidcObject.getSubject());

        assertTrue(groupContains(this.group1Reference, userDocument.getFullName()));
        assertTrue(groupContains(this.group2Reference, userDocument.getFullName()));
        assertFalse(groupContains(this.existinggroupReference, userDocument.getFullName()));

        assertEquals("User [XWiki.issuer-subject] already exist in group [xwiki:XWiki.group1]",
            this.logCapture.getMessage(0));
    }

    @Test
    void updateUserInfoWithCustomNameAndIdPattern()
        throws XWikiException, QueryException, OIDCProviderException, URISyntaxException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORMATER,
            "custom-${oidc.user.mail}-${oidc.user.mail.upperCase}-${oidc.user.mail.clean.upperCase}");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORBIDDENPATTERN, "@");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORBIDDENREPLACEMENT, "_AT_");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_SUBJECTFORMATER,
            "custom-${oidc.user.mail}-${oidc.user.mail.upperCase}-${oidc.user.mail.clean.upperCase}");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_USER_SUBJECTFORBIDDENPATTERN, "com");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_USER_SUBJECTFORBIDDENREPLACEMENT, "MOC");

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        Address address = new Address();
        address.setFormatted("address");
        userInfo.setPreferredUsername("preferredUserName");
        userInfo.setAddress(address);
        userInfo.setEmailAddress("mail@domain.com");
        userInfo.setFamilyName("familyName");
        userInfo.setGivenName("givenName");
        userInfo.setPhoneNumber("phoneNumber");
        userInfo.setLocale("fr");
        userInfo.setZoneinfo("timezone");
        userInfo.setWebsite(new URI("http://website"));

        Principal principal = this.manager.updateUser(userInfo);

        assertEquals("xwiki:XWiki.custom-mail@domain\\.com-MAIL@DOMAIN\\.COM-MAIL_AT_DOMAIN\\.COM",
            principal.getName());

        XWikiDocument userDocument =
            this.oldcore.getSpyXWiki().getDocument(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(),
                "XWiki", "custom-mail@domain.com-MAIL@DOMAIN.COM-MAIL_AT_DOMAIN.COM"), this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        assertNotNull(userObject);
        assertEquals("address", userObject.getStringValue("address"));
        assertEquals("mail@domain.com", userObject.getStringValue("email"));
        assertEquals("familyName", userObject.getStringValue("last_name"));
        assertEquals("givenName", userObject.getStringValue("first_name"));
        assertEquals("phoneNumber", userObject.getStringValue("phone"));

        OIDCUser oidcObject = new OIDCUser(userDocument.getXObject(this.oidcClassReference));

        assertNotNull(oidcObject);
        assertEquals("http://issuer", oidcObject.getIssuer());
        assertEquals("custom-mail@domain.com-MAIL@DOMAIN.COM-MAIL@DOMAIN.MOC", oidcObject.getSubject());
    }

    @Test
    void updateUserWithCustomNameFromIdToken()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORMATER,
            "custom-${oidc.idtoken.employeeName}");

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        idToken.setClaim("employeeName", "Azul");
        this.configuration.setIdToken(idToken);
        UserInfo userInfo = new UserInfo(subject);

        Principal principal = this.manager.updateUser(userInfo);
        assertNotNull(principal);

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "custom-Azul"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());
    }

    @Test
    void updateUserInfoWithAllowedGroup()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        Principal principal = this.manager.updateUser(userInfo);

        assertNotNull(principal);
    }

    @Test
    void updateUserInfoWithCreateUserDisabled()
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CREATE_USER, false);

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        OIDCProviderException exception =
            assertThrows(OIDCProviderException.class, () -> this.manager.updateUser(userInfo));
        assertEquals(
            "The user is not allowed to authenticate because it does not have an existing account"
                + " and automatic user creation is disabled",
            exception.getMessage());
    }

    @Test
    void updateUserInfoWithCreateUserDisabledExistingUser() throws Exception
    {
        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        // Create the user while automatic creation is still enabled
        Principal principal = this.manager.updateUser(userInfo);
        assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        Query query = mock(Query.class);
        when(this.queryManager.createQuery(Mockito.anyString(), Mockito.anyString())).thenReturn(query);
        when(query.bindValue(Mockito.anyString(), Mockito.any())).thenReturn(query);
        when(query.execute()).thenReturn(Arrays.asList("XWiki.issuer-subject"));

        // Disable automatic creation: existing users should still be allowed to authenticate and be updated
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CREATE_USER, false);

        userInfo.setGivenName("updatedGivenName");
        Principal updatedPrincipal = this.manager.updateUser(userInfo);
        assertEquals("xwiki:XWiki.issuer-subject", updatedPrincipal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());
        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));
        assertEquals("updatedGivenName", userObject.getStringValue("first_name"));
    }

    @Test
    void updateUserInfoWithNotAllowedGroup()
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup2", "pgroup3"));

        assertThrows(OIDCProviderException.class, () -> this.manager.updateUser(userInfo));
    }

    @Test
    void updateUserInfoWithForbiddenGroup()
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        assertThrows(OIDCProviderException.class, () -> this.manager.updateUser(userInfo));
    }

    @Test
    void updateUserInfoWithNotForbiddenGroup()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup2", "pgroup3"));

        Principal principal = this.manager.updateUser(userInfo);

        assertNotNull(principal);
    }

    @Test
    void updateUserInfoWithAllowedAndForbiddenGroup()
        throws XWikiException, QueryException, OIDCProviderException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Subject subject = new Subject("subject");
        UserInfo userInfo = new UserInfo(subject);

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        assertNotNull(this.manager.updateUser(userInfo));

        userInfo.setClaim("groupclaim", Arrays.asList("otherpgroup1", "otherpgroup3"));

        assertThrows(OIDCProviderException.class, () -> this.manager.updateUser(userInfo),
            "The user is not allowed to authenticate because it's not a member of the following groups: [pgroup1, pgroup2]");

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM,
            "custom.customgroupclaim");
        userInfo.setClaim("custom", Collections.singletonMap("customgroupclaim", Arrays.asList("pgroup1", "pgroup3")));

        assertNotNull(this.manager.updateUser(userInfo));

        userInfo.setClaim("custom",
            Collections.singletonMap("customgroupclaim", Arrays.asList("otherpgroup1", "otherpgroup3")));

        assertThrows(OIDCProviderException.class, () -> this.manager.updateUser(userInfo),
            "The user is not allowed to authenticate because it's not a member of the following groups: [pgroup1, pgroup2]");
    }

    // FIXME it would be nice to test updateUserInfoAsync, especially the fact that the execution happens
    // outside the http request, clearing the session from this.configuration when the code actually runs in
    // XWiki.

    @Test
    void getUserInfoRefreshesExpiredTokenValue() throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, "mysecret");

        this.configuration.setAccessToken(new BearerAccessToken("expiredaccesstoken", 0, this.configuration.getScope()),
            new RefreshToken("validrefreshtoken"));
        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
            assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
            assertEquals("refreshedvalidrefreshtoken", this.configuration.getRefreshToken().getValue());
        } finally {
            server.stop(0);
        }
    }

    private void assertRefreshFailure(String refreshToken, String expectedMessage) throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, "mysecret");

        this.configuration.setAccessToken(new BearerAccessToken("expiredaccesstoken", 0, this.configuration.getScope()),
            new RefreshToken(refreshToken));
        HttpServer server = startServer();
        try {
            InvalidAccessTokenException exception =
                assertThrows(InvalidAccessTokenException.class, () -> this.manager.getUserInfo());
            assertEquals(expectedMessage, exception.getMessage());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getUserInfoWhenRefreshTokenIsRejectedWithOAuth2Error() throws Exception
    {
        assertRefreshFailure(EXPIRED_REFRESH_TOKEN, "Failed to refresh the access token: [invalid_grant] Token is not "
            + "active (HTTP status [400 Bad Request])");
    }

    @Test
    void getUserInfoWhenRefreshTokenIsRejectedWithoutOAuth2Error() throws Exception
    {
        assertRefreshFailure(REJECTED_REFRESH_TOKEN,
            "Failed to refresh the access token: Proxy error (HTTP status [502 Bad Gateway])");
    }

    @Test
    void getUserInfoRefreshesExpiredTokenWithoutNewRefreshToken() throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, "mysecret");

        this.configuration.setAccessToken(new BearerAccessToken("expiredaccesstoken", 0, this.configuration.getScope()),
            new RefreshToken(NOT_ROTATED_REFRESH_TOKEN));
        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
            assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
            // The current refresh token is kept to be able to refresh the access token again later
            assertEquals(NOT_ROTATED_REFRESH_TOKEN, this.configuration.getRefreshToken().getValue());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getUserInfoRefreshesExpiredTokenWithClientSecretBasic() throws Exception
    {
        prepareExpiredAccessToken("mysecret");

        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
        } finally {
            server.stop(0);
        }

        assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
        // The client is authenticated with client_secret_basic by default
        String basic = Base64.getEncoder().encodeToString("myclientid:mysecret".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of("Basic " + basic), this.tokenRequestAuthorizations);
        assertFalse(this.tokenRequestParameters.get(0).containsKey("client_secret"));
    }

    @Test
    void getUserInfoRefreshesExpiredTokenWithClientSecretPost() throws Exception
    {
        prepareExpiredAccessToken("mysecret");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_ENDPOINT_TOKEN_AUTH_METHOD,
            "client_secret_post");

        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
        } finally {
            server.stop(0);
        }

        assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
        // The client is authenticated with the configured method, the secret is sent in the body
        assertEquals(List.of("null"), this.tokenRequestAuthorizations);
        assertEquals("myclientid", this.tokenRequestParameters.get(0).get("client_id"));
        assertEquals("mysecret", this.tokenRequestParameters.get(0).get("client_secret"));
    }

    @Test
    void getUserInfoRefreshesExpiredTokenWithoutSecret() throws Exception
    {
        prepareExpiredAccessToken(null);

        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
        } finally {
            server.stop(0);
        }

        assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
        // A public client only indicates its identifier
        assertEquals(List.of("null"), this.tokenRequestAuthorizations);
        assertEquals("myclientid", this.tokenRequestParameters.get(0).get("client_id"));
        assertFalse(this.tokenRequestParameters.get(0).containsKey("client_secret"));
    }

    /**
     * Configure the client and put an expired access token in the session, so that getting the user information
     * requires refreshing it.
     *
     * @param secret the secret of the client, {@code null} for a public client
     */
    private void prepareExpiredAccessToken(String secret)
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        if (secret != null) {
            this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, secret);
        }

        this.configuration.setAccessToken(new BearerAccessToken("expiredaccesstoken", 0, this.configuration.getScope()),
            new RefreshToken("validrefreshtoken"));
    }

    @Test
    void getUserInfoDoesNotRefreshNonExpiredToken() throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, "mysecret");

        this.configuration.setAccessToken(new BearerAccessToken("validaccesstoken", 0, this.configuration.getScope()),
            new RefreshToken("validrefreshtoken"));
        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
            assertEquals("validaccesstoken", this.configuration.getAccessToken().getValue());
            assertEquals("validrefreshtoken", this.configuration.getRefreshToken().getValue());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getUserInfoRefreshesExpiredTokenExpiredLifetime() throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, "mysecret");

        this.configuration.setAccessToken(new BearerAccessToken("validaccesstoken", 1, this.configuration.getScope()),
            new RefreshToken("validrefreshtoken"));
        HttpServer server = startServer();
        try {
            Thread.sleep(1100);
            this.manager.getUserInfo();
            assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
            assertEquals("refreshedvalidrefreshtoken", this.configuration.getRefreshToken().getValue());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getUserInfoRefreshUpdatesIdToken() throws Exception
    {
        JWT currentIdToken = prepareIdTokenRefresh();
        this.refreshedIdToken = signedIdToken(refreshIdTokenClaims().build(), this.providerKey);

        refreshAccessTokenThroughUserInfo();

        // The ID token sent with the refreshed access token replaces the one received at authentication
        assertEquals(this.refreshedIdToken.serialize(), this.configuration.getIdTokenJWT().serialize());
        assertEquals(this.refreshedIdToken.getJWTClaimsSet().getIssueTime(),
            this.configuration.getIdToken().getIssueTime());
        assertNotEquals(currentIdToken.serialize(), this.configuration.getIdTokenJWT().serialize());
    }

    @Test
    void getUserInfoRefreshKeepsIdTokenWithoutNewOne() throws Exception
    {
        JWT currentIdToken = prepareIdTokenRefresh();

        refreshAccessTokenThroughUserInfo();

        assertEquals(currentIdToken.serialize(), this.configuration.getIdTokenJWT().serialize());
    }

    @Test
    void getUserInfoRefreshIgnoresIdTokenWithAnotherSubject() throws Exception
    {
        JWT currentIdToken = prepareIdTokenRefresh();
        this.refreshedIdToken =
            signedIdToken(refreshIdTokenClaims().subject("othersubject").build(), this.providerKey);

        refreshAccessTokenThroughUserInfo();

        // The new ID token does not describe the same authentication so it's ignored, but the access token is still
        // refreshed
        assertEquals(currentIdToken.serialize(), this.configuration.getIdTokenJWT().serialize());
        assertEquals("subject", this.configuration.getIdToken().getSubject().getValue());
        assertEquals(1, this.logCapture.size());
        assertEquals("Ignored the ID token sent by the OpenID Connect provider with the refreshed access token, the "
            + "current one is kept: BadJWTException: The [sub] claim is not the same as in the current ID token",
            this.logCapture.getMessage(0));
    }

    @Test
    void getUserInfoRefreshIgnoresIdTokenWithAnotherAuthenticationTime() throws Exception
    {
        JWT currentIdToken = prepareIdTokenRefresh();
        this.refreshedIdToken = signedIdToken(
            refreshIdTokenClaims().claim("auth_time", AUTHENTICATION_TIME / 1000 + 60).build(), this.providerKey);

        refreshAccessTokenThroughUserInfo();

        assertEquals(currentIdToken.serialize(), this.configuration.getIdTokenJWT().serialize());
        assertEquals(1, this.logCapture.size());
        assertEquals("Ignored the ID token sent by the OpenID Connect provider with the refreshed access token, the "
            + "current one is kept: BadJWTException: The [auth_time] claim is not the same as in the current ID token",
            this.logCapture.getMessage(0));
    }

    @Test
    void getUserInfoRefreshIgnoresIdTokenWithInvalidSignature() throws Exception
    {
        JWT currentIdToken = prepareIdTokenRefresh();
        // Signed with a key which is not the one of the provider
        this.refreshedIdToken =
            signedIdToken(refreshIdTokenClaims().build(), new RSAKeyGenerator(2048).keyID(KEY_ID).generate());

        refreshAccessTokenThroughUserInfo();

        assertEquals(currentIdToken.serialize(), this.configuration.getIdTokenJWT().serialize());
        assertEquals(1, this.logCapture.size());
        assertTrue(this.logCapture.getMessage(0).startsWith("Ignored the ID token sent by the OpenID Connect "
            + "provider with the refreshed access token, the current one is kept: "),
            () -> "Unexpected log: " + this.logCapture.getMessage(0));
    }

    /**
     * Configure a client of the fake provider whose session contains an expired access token and an ID token.
     *
     * @return the ID token received at authentication
     */
    private JWT prepareIdTokenRefresh() throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, "myclientid");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_PROVIDER, "http://localhost:8081/");
        this.oldcore.getConfigurationSource()
            .setProperty(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO, "http://localhost:8081/userinfo");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, "mysecret");

        this.providerKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();

        // Validating the ID token requires the URLs of the endpoints of XWiki as a client of the provider
        XWikiURLFactory urlFactory = mock(XWikiURLFactory.class);
        when(urlFactory.getServerURL(any())).thenReturn(new URL("http://wiki/"));
        this.oldcore.getXWikiContext().setURLFactory(urlFactory);
        doReturn("xwiki/").when(this.oldcore.getSpyXWiki()).getWebAppPath(any());

        // The user info endpoint rejects this access token, which makes it refreshed
        this.configuration.setAccessToken(new BearerAccessToken("expiredaccesstoken", 0, this.configuration.getScope()),
            new RefreshToken("validrefreshtoken"));

        JWT currentIdToken = signedIdToken(idTokenClaims(AUTHENTICATION_TIME).build(), this.providerKey);
        this.configuration.setIdTokenJWT(currentIdToken);
        this.configuration.setIdToken(new IDTokenClaimsSet(currentIdToken.getJWTClaimsSet()));

        return currentIdToken;
    }

    private void refreshAccessTokenThroughUserInfo() throws Exception
    {
        HttpServer server = startServer();
        try {
            this.manager.getUserInfo();
        } finally {
            server.stop(0);
        }

        assertEquals("refreshedaccesstoken", this.configuration.getAccessToken().getValue());
    }

    /**
     * @return the claims of an ID token issued by the fake provider when refreshing the access token, describing the
     *     same authentication as the current ID token
     */
    private JWTClaimsSet.Builder refreshIdTokenClaims()
    {
        return idTokenClaims(System.currentTimeMillis());
    }

    private JWTClaimsSet.Builder idTokenClaims(long issueTime)
    {
        return new JWTClaimsSet.Builder().issuer("http://localhost:8081/").subject("subject").audience("myclientid")
            .issueTime(new Date(issueTime / 1000 * 1000)).expirationTime(new Date(issueTime + 3600000L))
            .claim("auth_time", AUTHENTICATION_TIME / 1000);
    }

    private JWT signedIdToken(JWTClaimsSet claims, RSAKey key) throws JOSEException
    {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(), claims);
        jwt.sign(new RSASSASigner(key));

        return jwt;
    }

    @Test
    void logoutWithGetEndpointMethod() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.GET);

        this.manager.logout();

        // The logout request is sent through a redirect
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(location.capture());
        verify(this.templateManager, never()).render(LOGOUT_TEMPLATE);

        assertTrue(location.getValue().startsWith(LOGOUT_ENDPOINT + '?'),
            () -> "Unexpected logout location: " + location.getValue());
        assertEquals(logoutParameters(), URLUtils.parseParameters(URI.create(location.getValue()).getRawQuery()));
    }

    @Test
    void logoutWithPostEndpointMethod() throws Exception
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_PROVIDER, PROVIDER);
        XWikiResponse response = prepareLogout(LogoutMethod.POST);
        StringWriter content = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(content));
        when(this.templateManager.render(LOGOUT_TEMPLATE)).thenReturn(LOGOUT_FORM);
        ScriptContext scriptContext = prepareScriptContext();

        this.manager.logout();

        // The logout request is sent by the browser through a form instead of a redirect
        verify(response, never()).sendRedirect(anyString());
        assertEquals(LOGOUT_FORM, content.toString());

        // The form is filled with the logout request and the issuer to display
        assertEquals(LOGOUT_ENDPOINT, scriptContext.getAttribute("logoutEndpoint"));
        assertEquals(logoutParameters(), scriptContext.getAttribute("logoutParameters"));
        assertEquals(PROVIDER, scriptContext.getAttribute("logoutIssuer"));
    }

    @Test
    void logoutWithPostEndpointMethodWithoutProvider() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.POST);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        ScriptContext scriptContext = prepareScriptContext();

        this.manager.logout();

        verify(this.templateManager).render(LOGOUT_TEMPLATE);
        assertEquals(logoutParameters(), scriptContext.getAttribute("logoutParameters"));

        // There is no issuer to display when no provider is configured
        assertNull(scriptContext.getAttribute("logoutIssuer"));
    }

    @Test
    void logoutWithServerEndpointMethod() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.SERVER);
        List<LogoutServerRequest> requests = new ArrayList<>();
        HttpServer server = startLogoutServer(HttpURLConnection.HTTP_OK, requests);
        try {
            this.manager.logout();
        } finally {
            server.stop(0);
        }

        // The logout request is sent by XWiki, without post logout redirect since the browser is not involved, and
        // without client authentication since no secret is configured
        assertEquals(1, requests.size());
        assertEquals("POST", requests.get(0).method);
        assertNull(requests.get(0).authorization);
        assertEquals(Map.of("id_token_hint", List.of(this.idToken.serialize()), "client_id", List.of(CLIENT_ID)),
            requests.get(0).parameters);

        // XWiki redirects the browser itself
        verify(response).sendRedirect(AFTER_LOGOUT_URL);
        verify(this.templateManager, never()).render(LOGOUT_TEMPLATE);
    }

    @Test
    void logoutWithServerEndpointMethodAndClientSecretBasic() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.SERVER);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, CLIENT_SECRET);
        List<LogoutServerRequest> requests = new ArrayList<>();
        HttpServer server = startLogoutServer(HttpURLConnection.HTTP_OK, requests);
        try {
            this.manager.logout();
        } finally {
            server.stop(0);
        }

        // The client is authenticated as for the token endpoint, which already indicates the client
        assertEquals(1, requests.size());
        assertEquals(
            "Basic " + Base64.getEncoder().encodeToString((CLIENT_ID + ':' + CLIENT_SECRET).getBytes(
                StandardCharsets.UTF_8)), requests.get(0).authorization);
        assertEquals(Map.of("id_token_hint", List.of(this.idToken.serialize())), requests.get(0).parameters);

        verify(response).sendRedirect(AFTER_LOGOUT_URL);
    }

    @Test
    void logoutWithServerEndpointMethodAndClientSecretPost() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.SERVER);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SECRET, CLIENT_SECRET);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_ENDPOINT_TOKEN_AUTH_METHOD,
            "client_secret_post");
        List<LogoutServerRequest> requests = new ArrayList<>();
        HttpServer server = startLogoutServer(HttpURLConnection.HTTP_OK, requests);
        try {
            this.manager.logout();
        } finally {
            server.stop(0);
        }

        assertEquals(1, requests.size());
        assertNull(requests.get(0).authorization);
        assertEquals(Map.of("id_token_hint", List.of(this.idToken.serialize()), "client_id", List.of(CLIENT_ID),
            "client_secret", List.of(CLIENT_SECRET)), requests.get(0).parameters);

        verify(response).sendRedirect(AFTER_LOGOUT_URL);
    }

    @Test
    void logoutWithServerEndpointMethodWithoutIdTokenHint() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.SERVER);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_SKIP_LOGOUT_ID_TOKEN, true);
        List<LogoutServerRequest> requests = new ArrayList<>();
        HttpServer server = startLogoutServer(HttpURLConnection.HTTP_OK, requests);
        try {
            this.manager.logout();
        } finally {
            server.stop(0);
        }

        // Without ID token the provider cannot know which session to end
        assertEquals(List.of(), requests);
        assertEquals(1, this.logCapture.size());
        assertEquals("Skipped the server side logout from the OpenID Connect provider because there is no ID token to "
            + "indicate the session to end (it is either missing or excluded by the configuration).",
            this.logCapture.getMessage(0));

        verify(response).sendRedirect(AFTER_LOGOUT_URL);
    }

    @Test
    void logoutWithServerEndpointMethodWhenProviderFails() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.SERVER);
        List<LogoutServerRequest> requests = new ArrayList<>();
        HttpServer server = startLogoutServer(HttpURLConnection.HTTP_INTERNAL_ERROR, requests);
        try {
            this.manager.logout();
        } finally {
            server.stop(0);
        }

        assertEquals(1, requests.size());
        assertEquals(1, this.logCapture.size());
        assertEquals("The OpenID Connect provider logout endpoint [" + serverLogoutEndpoint(server)
            + "] answered with status [500]: the user might still be logged in on the provider side",
            this.logCapture.getMessage(0));

        // The user is still logged out from XWiki
        verify(response).sendRedirect(AFTER_LOGOUT_URL);
    }

    @Test
    void logoutWithServerEndpointMethodWhenProviderIsUnreachable() throws Exception
    {
        XWikiResponse response = prepareLogout(LogoutMethod.SERVER);
        // Get a free port and release it so that nothing answers there
        HttpServer server = startLogoutServer(HttpURLConnection.HTTP_OK, new ArrayList<>());
        server.stop(0);

        this.manager.logout();

        assertEquals(1, this.logCapture.size());
        assertTrue(this.logCapture.getMessage(0).startsWith(
            "Failed to send the logout request to the OpenID Connect provider logout endpoint ["
                + serverLogoutEndpoint(server) + "], the user might still be logged in on the provider side: "),
            () -> "Unexpected log: " + this.logCapture.getMessage(0));

        verify(response).sendRedirect(AFTER_LOGOUT_URL);
    }

    /**
     * A request received by the provider logout endpoint.
     */
    private static final class LogoutServerRequest
    {
        private final String method;

        private final String authorization;

        private final Map<String, List<String>> parameters;

        LogoutServerRequest(HttpExchange exchange) throws IOException
        {
            this.method = exchange.getRequestMethod();
            this.authorization = exchange.getRequestHeaders().getFirst("Authorization");
            this.parameters = URLUtils.parseParameters(
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /**
     * Start a provider logout endpoint and configure it as the logout endpoint to use.
     *
     * @param status the status to answer with
     * @param requests the requests received by the endpoint
     * @return the started server
     */
    private HttpServer startLogoutServer(int status, List<LogoutServerRequest> requests) throws IOException
    {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        httpServer.createContext("/logout", exchange -> {
            requests.add(new LogoutServerRequest(exchange));
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        httpServer.start();

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_ENDPOINT_LOGOUT,
            serverLogoutEndpoint(httpServer));

        return httpServer;
    }

    private String serverLogoutEndpoint(HttpServer server)
    {
        return "http://" + server.getAddress().getHostString() + ':' + server.getAddress().getPort() + "/logout";
    }

    /**
     * @return the script context in which the logout form content is expected
     */
    private ScriptContext prepareScriptContext()
    {
        ScriptContext scriptContext = new SimpleScriptContext();
        scriptContext.setBindings(new SimpleBindings(), ScriptContext.GLOBAL_SCOPE);
        when(this.scriptContextManager.getCurrentScriptContext()).thenReturn(scriptContext);

        return scriptContext;
    }

    /**
     * @param method the way to send the logout request to the provider
     * @return the response in which the logout request is expected
     */
    private XWikiResponse prepareLogout(LogoutMethod method)
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_CLIENTID, CLIENT_ID);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_ENDPOINT_LOGOUT,
            LOGOUT_ENDPOINT);
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_ENDPOINT_LOGOUT_METHOD, method);

        this.configuration.setIdTokenJWT(this.idToken);

        XWikiContext xcontext = this.oldcore.getXWikiContext();
        xcontext.setRequest(new XWikiServletRequestStub.Builder()
            .setRequestParameters(Map.of("xredirect", new String[] { AFTER_LOGOUT_URL })).build());
        XWikiResponse response = mock(XWikiResponse.class);
        xcontext.setResponse(response);

        return response;
    }

    /**
     * @return the parameters expected in the logout request
     */
    private Map<String, List<String>> logoutParameters()
    {
        return Map.of("id_token_hint", List.of(this.idToken.serialize()), "client_id", List.of(CLIENT_ID),
            "post_logout_redirect_uri", List.of(AFTER_LOGOUT_URL));
    }

    private HttpServer startServer() throws IOException
    {
        HttpServer httpServer =
            HttpServer.create(new InetSocketAddress(8081), 0); // or use InetSocketAddress(0) for ephemeral port
        httpServer.createContext("/.well-known/openid-configuration", exchange -> {
            JSONObject r = new JSONObject();
            r.put("issuer", "http://localhost:8081/");
            r.put("authorization_endpoint", "http://localhost:8081/auth");
            r.put("token_endpoint", "http://localhost:8081/token");
            r.put("jwks_uri", "http://localhost:8081/jwks");
            r.put("response_types_supported", new JSONArray(List.of("code", "token", "id_token")));
            r.put("subject_types_supported", new JSONArray(List.of("public")));
            r.put("id_token_signing_alg_values_supported", new JSONArray(List.of("RS256")));
            r.put("claims_supported", new JSONArray(List.of("sub", "iss", "aud", "iat", "exp", "email", "name")));
            sendResponse(exchange, r, HttpURLConnection.HTTP_OK);
        });

        httpServer.createContext("/jwks", exchange -> {
            byte[] response = new JWKSet(this.providerKey.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        httpServer.createContext("/userinfo", exchange -> {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            String accessToken = "expiredaccesstoken";
            if (authorization.startsWith("Bearer ")) {
                accessToken = authorization.substring(7);
            }
            JSONObject r = new JSONObject();
            int httpCode = HttpURLConnection.HTTP_OK;
            if ("expiredaccesstoken".equals(accessToken)) {
                httpCode = handleInvalidToken(r);
            } else {
                r.put("sub", "1234567890");
                r.put("name", "John Doe");
            }
            sendResponse(exchange, r, httpCode);
        });

        httpServer.createContext("/token", exchange -> {
            int httpCode = HttpURLConnection.HTTP_OK;
            JSONObject r = new JSONObject();
            boolean authorized;
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            Map<String, String> p = parseURLEncodedBody(exchange);
            this.tokenRequestAuthorizations.add(String.valueOf(authorization));
            this.tokenRequestParameters.add(p);
            if (EXPIRED_REFRESH_TOKEN.equals(p.get("refresh_token"))) {
                r.put("error", "invalid_grant");
                r.put("error_description", "Token is not active");
                sendResponse(exchange, r, HttpURLConnection.HTTP_BAD_REQUEST);
                return;
            }
            if (REJECTED_REFRESH_TOKEN.equals(p.get("refresh_token"))) {
                byte[] response = "Proxy error".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain");
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_GATEWAY, response.length);
                exchange.getResponseBody().write(response);
                exchange.close();
                return;
            }
            if (authorization != null && authorization.startsWith("Basic ")) {
                // client_secret_basic
                String[] decoded = new String(Base64.getDecoder().decode(authorization.substring(6))).split(":");
                authorized = decoded[0].equals("myclientid") && decoded[1].equals("mysecret");
            } else {
                // client_secret_post, or a public client which only indicates its identifier
                authorized = "myclientid".equals(p.get("client_id"))
                    && (!p.containsKey("client_secret") || "mysecret".equals(p.get("client_secret")));
            }
            if (authorized) {
                r.put("access_token", "refreshedaccesstoken");
                // A provider is not required to issue a new refresh token
                if (!NOT_ROTATED_REFRESH_TOKEN.equals(p.get("refresh_token"))) {
                    r.put("refresh_token", "refreshed" + p.get("refresh_token"));
                }
                r.put("token_type", "Bearer");
                r.put("expires_in", 3600);
                if (this.refreshedIdToken != null) {
                    r.put("id_token", this.refreshedIdToken.serialize());
                }
            } else {
                httpCode = handleInvalidToken(r);
            }
            sendResponse(exchange, r, httpCode);
        });

        httpServer.start();
        return httpServer;
    }

    private static void sendResponse(HttpExchange exchange, JSONObject r, int httpCode) throws IOException
    {
        byte[] response = r.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(httpCode, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static int handleInvalidToken(JSONObject r)
    {
        int httpCode;
        httpCode = HttpURLConnection.HTTP_UNAUTHORIZED;
        r.put("error", BearerTokenError.INVALID_TOKEN.getCode());
        r.put("reason", "This token is invalid");
        return httpCode;
    }

    private Map<String, String> parseURLEncodedParameters(String s)
    {
        String[] split = s.split("&");
        Map<String, String> m = new HashMap<>(split.length);
        for (String pair : split) {
            String[] v = pair.split("=");
            if (v.length == 2) {
                m.put(v[0], v[1]);
            }
        }
        return m;
    }

    private Map<String, String> parseURLEncodedBody(HttpExchange exchange)
    {
        String body = new BufferedReader(
            new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"));

        return parseURLEncodedParameters(body);
    }
}
