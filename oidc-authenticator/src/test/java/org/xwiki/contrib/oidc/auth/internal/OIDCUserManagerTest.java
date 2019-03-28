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
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections4.ListUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.container.Container;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUser;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserClassDocumentInitializer;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.localization.ContextualLocalizationManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.properties.ConverterManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.security.authorization.AuthorExecutor;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.template.TemplateManager;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.mockito.MockitoComponentMockingRule;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.MandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcoreRule;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCUserManager}.
 * 
 * @version $Id$
 */
@ComponentList({ OIDCManager.class, OIDCClientConfiguration.class, OIDCUserStore.class,
    OIDCUserClassDocumentInitializer.class })
@ReferenceComponentList
public class OIDCUserManagerTest
{
    private MockitoComponentMockingRule<OIDCUserManager> mocker =
        new MockitoComponentMockingRule<>(OIDCUserManager.class);

    @Rule
    public MockitoOldcoreRule oldcore = new MockitoOldcoreRule(this.mocker);

    private DocumentReference oidcClassReference;

    private DocumentReference group1Reference;

    private DocumentReference group2Reference;

    private DocumentReference existinggroupReference;

    private DocumentReference pgroup1Reference;

    private DocumentReference pgroup2Reference;

    @Before
    public void before() throws Exception
    {
        this.mocker.registerMockComponent(InstanceIdManager.class);
        this.mocker.registerMockComponent(TemplateManager.class);
        this.mocker.registerMockComponent(AuthorExecutor.class);
        this.mocker.registerMockComponent(Container.class);
        this.mocker.registerMockComponent(ConverterManager.class);
        this.mocker.registerMockComponent(MandatoryDocumentInitializer.class, "XWiki.XWikiRights");
        this.mocker.registerMockComponent(ContextualLocalizationManager.class);
        this.mocker.registerMockComponent(SheetBinder.class, "document");

        this.oldcore.mockQueryManager();
        when(this.oldcore.getQueryManager().createQuery(Mockito.anyString(), Mockito.anyString()))
            .thenReturn(mock(Query.class));

        MandatoryDocumentInitializer initializer =
            this.mocker.getInstance(MandatoryDocumentInitializer.class, OIDCUser.CLASS_FULLNAME);

        this.oidcClassReference =
            new DocumentReference(OIDCUser.CLASS_REFERENCE, this.oldcore.getXWikiContext().getWikiReference());
        XWikiDocument classDocument =
            this.oldcore.getSpyXWiki().getDocument(this.oidcClassReference, this.oldcore.getXWikiContext());
        initializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, this.oldcore.getXWikiContext());

        this.group1Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "group1");
        this.group2Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "group2");
        this.existinggroupReference =
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "existinggroup");
        this.pgroup1Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "pgroup1");
        this.pgroup2Reference = new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "pgroup2");
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

    // Tests

    @Test
    public void updateUserInfo()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException, URISyntaxException
    {
        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
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

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertEquals("xwiki:XWiki.issuer-preferredUserName", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-preferredUserName"),
            this.oldcore.getXWikiContext());

        Assert.assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        Assert.assertNotNull(userObject);
        Assert.assertEquals("address", userObject.getStringValue("address"));
        Assert.assertEquals("mail@domain.com", userObject.getStringValue("email"));
        Assert.assertEquals("familyName", userObject.getStringValue("last_name"));
        Assert.assertEquals("givenName", userObject.getStringValue("first_name"));
        Assert.assertEquals("phoneNumber", userObject.getStringValue("phone"));

        OIDCUser oidcObject = (OIDCUser) userDocument.getXObject(this.oidcClassReference);

        Assert.assertNotNull(oidcObject);
        Assert.assertEquals("http://issuer", oidcObject.getIssuer());
        Assert.assertEquals("subject", oidcObject.getSubject());
    }

    @Test
    public void updateUserInfoWithGroupSyncWithDefaultGroupsClaim()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS,
                Arrays.asList(OIDCClientConfiguration.DEFAULT_GROUPSCLAIM)));

        userInfo.setClaim(OIDCClientConfiguration.DEFAULT_GROUPSCLAIM, Arrays.asList("pgroup1", "pgroup2"));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        Assert.assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        Assert.assertNotNull(userObject);

        OIDCUser oidcObject = (OIDCUser) userDocument.getXObject(this.oidcClassReference);

        Assert.assertNotNull(oidcObject);
        Assert.assertEquals("http://issuer", oidcObject.getIssuer());
        Assert.assertEquals("subject", oidcObject.getSubject());

        Assert.assertTrue(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        Assert.assertTrue(groupContains(this.pgroup2Reference, userDocument.getFullName()));
    }

    @Test
    public void updateUserInfoWithGroupSyncWithoutMapping()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, "XWiki.issuer-subject");

        Assert.assertFalse(groupContains(this.group1Reference, userFullName));
        Assert.assertFalse(groupContains(this.group2Reference, userFullName));
        Assert.assertTrue(groupContains(this.existinggroupReference, userFullName));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        Assert.assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        Assert.assertNotNull(userObject);

        OIDCUser oidcObject = (OIDCUser) userDocument.getXObject(this.oidcClassReference);

        Assert.assertNotNull(oidcObject);
        Assert.assertEquals("http://issuer", oidcObject.getIssuer());
        Assert.assertEquals("subject", oidcObject.getSubject());

        Assert.assertTrue(groupContains(this.pgroup1Reference, userDocument.getFullName()));
        Assert.assertTrue(groupContains(this.pgroup2Reference, userDocument.getFullName()));
        Assert.assertFalse(groupContains(this.existinggroupReference, userDocument.getFullName()));
    }

    @Test
    public void updateUserInfoWithGroupSyncWithMapping()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_MAPPING,
            Arrays.asList("group1=pgroup1", "group1=pgroup2", "XWiki.group2=pgroup2", "existinggroup=othergroup"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup2"));

        String userFullName = "XWiki.issuer-subject";

        when(this.oldcore.getMockGroupService().getAllGroupsNamesForMember(userFullName, 0, 0,
            this.oldcore.getXWikiContext())).thenReturn(Arrays.asList("XWiki.existinggroup"));
        addMember(this.existinggroupReference, "XWiki.issuer-subject");

        Assert.assertFalse(groupContains(this.group1Reference, userFullName));
        Assert.assertFalse(groupContains(this.group2Reference, userFullName));
        Assert.assertTrue(groupContains(this.existinggroupReference, userFullName));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertEquals("xwiki:XWiki.issuer-subject", principal.getName());

        XWikiDocument userDocument = this.oldcore.getSpyXWiki().getDocument(
            new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "issuer-subject"),
            this.oldcore.getXWikiContext());

        Assert.assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        Assert.assertNotNull(userObject);

        OIDCUser oidcObject = (OIDCUser) userDocument.getXObject(this.oidcClassReference);

        Assert.assertNotNull(oidcObject);
        Assert.assertEquals("http://issuer", oidcObject.getIssuer());
        Assert.assertEquals("subject", oidcObject.getSubject());

        Assert.assertTrue(groupContains(this.group1Reference, userDocument.getFullName()));
        Assert.assertTrue(groupContains(this.group2Reference, userDocument.getFullName()));
        Assert.assertFalse(groupContains(this.existinggroupReference, userDocument.getFullName()));
    }

    @Test
    public void updateUserInfoWithCustomNameAndIdPattern()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException, URISyntaxException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_NAMEFORMATER,
            "custom-${oidc.user.mail}-${oidc.user.mail.upperCase}-${oidc.user.mail.clean.upperCase}");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USER_SUBJECTFORMATER,
            "custom-${oidc.user.mail}-${oidc.user.mail.upperCase}-${oidc.user.mail.clean.upperCase}");

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
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

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertEquals("xwiki:XWiki.custom-mail@domain\\.com-MAIL@DOMAIN\\.COM-MAILDOMAINCOM",
            principal.getName());

        XWikiDocument userDocument =
            this.oldcore.getSpyXWiki().getDocument(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(),
                "XWiki", "custom-mail@domain.com-MAIL@DOMAIN.COM-MAILDOMAINCOM"), this.oldcore.getXWikiContext());

        Assert.assertFalse(userDocument.isNew());

        BaseObject userObject = userDocument
            .getXObject(new DocumentReference(this.oldcore.getXWikiContext().getWikiId(), "XWiki", "XWikiUsers"));

        Assert.assertNotNull(userObject);
        Assert.assertEquals("address", userObject.getStringValue("address"));
        Assert.assertEquals("mail@domain.com", userObject.getStringValue("email"));
        Assert.assertEquals("familyName", userObject.getStringValue("last_name"));
        Assert.assertEquals("givenName", userObject.getStringValue("first_name"));
        Assert.assertEquals("phoneNumber", userObject.getStringValue("phone"));

        OIDCUser oidcObject = (OIDCUser) userDocument.getXObject(this.oidcClassReference);

        Assert.assertNotNull(oidcObject);
        Assert.assertEquals("http://issuer", oidcObject.getIssuer());
        Assert.assertEquals("custom-mail@domain.com-MAIL@DOMAIN.COM-MAILDOMAINCOM", oidcObject.getSubject());
    }

    @Test
    public void updateUserInfoWithAllowedGroup()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertNotNull(principal);
    }

    @Test(expected = OIDCException.class)
    public void updateUserInfoWithNotAllowedGroup()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup2", "pgroup3"));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertNotNull(principal);
    }

    @Test(expected = OIDCException.class)
    public void updateUserInfoWithForbiddenGroup()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertNotNull(principal);
    }

    @Test
    public void updateUserInfoWithNotForbiddenGroup()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup2", "pgroup3"));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertNotNull(principal);
    }

    @Test
    public void updateUserInfoWithAllowedAndForbiddenGroup()
        throws XWikiException, QueryException, OIDCException, ComponentLookupException
    {
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_ALLOWED,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_FORBIDDEN,
            Arrays.asList("pgroup1", "pgroup2"));
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM, "groupclaim");
        this.oldcore.getConfigurationSource().setProperty(OIDCClientConfiguration.PROP_USERINFOCLAIMS,
            ListUtils.sum(OIDCClientConfiguration.DEFAULT_USERINFOCLAIMS, Arrays.asList(
                this.oldcore.getConfigurationSource().<String>getProperty(OIDCClientConfiguration.PROP_GROUPS_CLAIM))));

        Issuer issuer = new Issuer("http://issuer");
        Subject subject = new Subject("subject");
        IDTokenClaimsSet idToken =
            new IDTokenClaimsSet(issuer, subject, Collections.emptyList(), new Date(), new Date());
        UserInfo userInfo = new UserInfo(subject);

        userInfo.setClaim("groupclaim", Arrays.asList("pgroup1", "pgroup3"));

        Principal principal = this.mocker.getComponentUnderTest().updateUser(idToken, userInfo);

        Assert.assertNotNull(principal);
    }
}
