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
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Named;

import org.apache.commons.collections4.ListUtils;
import org.joda.time.LocalDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.xwiki.container.Container;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders;
import org.xwiki.contrib.oidc.auth.internal.store.DefaultOIDCUserStore;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserClassDocumentInitializer;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.auth.store.OIDCUser;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration;
import org.xwiki.contrib.oidc.provider.internal.session.OIDCClients;
import org.xwiki.contrib.oidc.provider.internal.session.ProviderOIDCSessions;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.environment.Environment;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.localization.ContextualLocalizationManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.properties.ConverterManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.security.authorization.AuthorExecutor;
import org.xwiki.template.TemplateManager;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.MandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCUserManager}.
 * 
 * @version $Id$
 */
@OldcoreTest
@ComponentList({OIDCManager.class, OIDCClientConfiguration.class, DefaultOIDCUserStore.class,
    OIDCProviderConfiguration.class, OIDCStore.class, ProviderOIDCSessions.class, OIDCClients.class,
    ClientProviders.class})
@ReferenceComponentList
class OIDCUserManagerTest
{
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

    @InjectMockComponents
    OIDCUserClassDocumentInitializer classInitializer;

    @InjectMockComponents
    OIDCUserManager manager;

    @InjectMockitoOldcore
    MockitoOldcore oldcore;

    @MockComponent
    OAuth2TokenStore tokenStore;

    private DocumentReference xwikiallgroupReference;

    private DocumentReference oidcClassReference;

    private DocumentReference group1Reference;

    private DocumentReference group2Reference;

    private DocumentReference existinggroupReference;

    private DocumentReference pgroup1Reference;

    private DocumentReference pgroup2Reference;

    @BeforeEach
    public void beforeEach() throws Exception
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
        throws XWikiException, QueryException, OIDCException, URISyntaxException, MalformedURLException
    {
        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
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

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS,
                Arrays.asList(OIDCClientConfiguration.DEFAULT_GROUPSCLAIM)));

        userInfo.setClaim(OIDCClientConfiguration.DEFAULT_GROUPSCLAIM, Arrays.asList("pgroup1", "pgroup2"));

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
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

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_INCLUDE,
            "^XWiki\\.[A-Za-z]*group[A-Za-z]*1$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
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

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_EXCLUDE,
            "^XWiki\\.[A-Za-z]*group[A-Za-z]*1$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
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

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_INCLUDE,
            "^.*pgroup.*$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING_EXCLUDE, ".*2$");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
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

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
        throws XWikiException, QueryException, OIDCException, MalformedURLException
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

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, "XWiki.issuer-subject");

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
    }

    @Test
    void updateUserInfoWithGroupSyncWithMapping()
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING,
            Arrays.asList("group1=pgroup1", "group1=pgroup2", "XWiki.group2=pgroup2", "existinggroup=othergroup"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, "XWiki.issuer-subject");

        assertFalse(groupContains(this.group1Reference, userFullName));
        assertFalse(groupContains(this.group2Reference, userFullName));
        assertTrue(groupContains(this.existinggroupReference, userFullName));

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

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
    }

    @Test
    void updateUserInfoWithCustomNameAndIdPattern()
        throws XWikiException, QueryException, OIDCException, URISyntaxException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORMATER,
            "custom-${oidc.user.mail}-${oidc.user.mail.upperCase}-${oidc.user.mail.clean.upperCase}");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_SUBJECTFORMATER,
            "custom-${oidc.user.mail}-${oidc.user.mail.upperCase}-${oidc.user.mail.clean.upperCase}");

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
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

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

        assertEquals("xwiki:XWiki.custom-mail@domain\\.com-MAIL@DOMAIN\\.COM-MAILDOMAINCOM", principal.getName());

        XWikiDocument userDocument =
            this.oldcore.getSpyXWiki().getDocument(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(),
                "XWiki", "custom-mail@domain.com-MAIL@DOMAIN.COM-MAILDOMAINCOM"), this.oldcore.getXWikiContext());

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
        assertEquals("custom-mail@domain.com-MAIL@DOMAIN.COM-MAILDOMAINCOM", oidcObject.getSubject());
    }

    @Test
    void updateUserWithCustomNameFromIdToken()
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORMATER,
            "custom-${oidc.idtoken.employeeName}");

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        idToken.setClaim("employeeName", "Azul");
        UserInfo userInfo = new UserInfo(subject);

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "custom-Azul"),
            this.oldcore.getXWikiContext());

        assertFalse(userDocument.isNew());
    }

    @Test
    void updateUserInfoWithAllowedGroup() throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

        assertNotNull(principal);
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

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup2", "pgroup3"));

        assertThrows(OIDCException.class, () -> this.manager.updateUser(idToken, userInfo, new BearerAccessToken()));
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

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        assertThrows(OIDCException.class, () -> this.manager.updateUser(idToken, userInfo, new BearerAccessToken()));
    }

    @Test
    void updateUserInfoWithNotForbiddenGroup()
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup2", "pgroup3"));

        Principal principal = this.manager.updateUser(idToken, userInfo, new BearerAccessToken());

        assertNotNull(principal);
    }

    @Test
    void updateUserInfoWithAllowedAndForbiddenGroup()
        throws XWikiException, QueryException, OIDCException, MalformedURLException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken = createIDTokenClaimsSet(issuer, subject);
        UserInfo userInfo = new UserInfo(subject);
        BearerAccessToken accessToken = new BearerAccessToken();

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        assertNotNull(this.manager.updateUser(idToken, userInfo, accessToken));

        userInfo.setClaim("groupclaim", Arrays.asList("otherpgroup1", "otherpgroup3"));

        assertThrows(OIDCException.class, () -> this.manager.updateUser(idToken, userInfo, accessToken),
            "The user is not allowed to authenticate because it's not a member of the following groups: [pgroup1, pgroup2]");

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM,
            "custom.customgroupclaim");
        userInfo.setClaim("custom", Collections.singletonMap("customgroupclaim", Arrays.asList("pgroup1", "pgroup3")));

        assertNotNull(this.manager.updateUser(idToken, userInfo, accessToken));

        userInfo.setClaim("custom",
            Collections.singletonMap("customgroupclaim", Arrays.asList("otherpgroup1", "otherpgroup3")));

        assertThrows(OIDCException.class, () -> this.manager.updateUser(idToken, userInfo, accessToken),
            "The user is not allowed to authenticate because it's not a member of the following groups: [pgroup1, pgroup2]");
    }
}
