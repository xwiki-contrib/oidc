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
package org.xwiki.contrib.oidc.consent.internal.store;

import java.util.Date;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceSerializer;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.filter.XWikiDocumentFilterUtils;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCConsentStore}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCConsentStoreTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    private static final DocumentReference OTHERUSER_REFERENCE = new DocumentReference("xwiki", "XWiki", "OtherUser");

    private static final LocalDocumentReference USERS_CLASS_REFERENCE =
        new LocalDocumentReference("XWiki", "XWikiUsers");

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    @MockComponent
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    // Used when an xobject is serialized as part of an error message
    @MockComponent
    private XWikiDocumentFilterUtils filterUtils;

    @InjectMockComponents
    private OIDCConsentClassDocumentInitializer classInitializer;

    @InjectMockComponents
    private OIDCConsentStore store;

    private UserReference user;

    private UserReference otherUser;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        // Make sure the consent class exist since creating a consent requires it
        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);

        this.user = mock(UserReference.class, "user");
        when(this.userReferenceSerializer.serialize(this.user)).thenReturn(USER_REFERENCE);
        this.otherUser = mock(UserReference.class, "otheruser");
        when(this.userReferenceSerializer.serialize(this.otherUser)).thenReturn(OTHERUSER_REFERENCE);

        // A user with two consents and a user xobject
        XWikiDocument userDocument = new XWikiDocument(USER_REFERENCE);
        userDocument.newXObject(USERS_CLASS_REFERENCE, xcontext);
        userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        this.oldcore.getSpyXWiki().saveDocument(userDocument, xcontext);
    }

    private XWikiDocument getUserDocument() throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(USER_REFERENCE, this.oldcore.getXWikiContext());
    }

    private BaseObject getConsentObject(int number) throws Exception
    {
        return getUserDocument().getXObject(BaseObjectOIDCConsent.REFERENCE, number);
    }

    private BaseObjectOIDCConsent getConsent(int number) throws Exception
    {
        return new BaseObjectOIDCConsent("id", getConsentObject(number), this.oldcore.getXWikiContext());
    }

    private void saveUserDocument(XWikiDocument userDocument) throws Exception
    {
        this.oldcore.getSpyXWiki().saveDocument(userDocument, this.oldcore.getXWikiContext());
    }

    /**
     * Create and store a token for one of the consents of {@link #USER_REFERENCE}.
     */
    private XWikiBearerAccessToken createAndSaveAccessToken(int number, Date expiration) throws Exception
    {
        BaseObjectOIDCConsent consent = getConsent(number);

        XWikiBearerAccessToken accessToken = this.store.createAccessToken(consent, expiration);

        saveUserDocument(consent.getOwnerDocument());

        return accessToken;
    }

    @Test
    void deleteConsent() throws Exception
    {
        this.store.deleteConsent(this.user, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]");

        assertNull(getConsentObject(0));
        // The other consent and the user xobject are untouched
        assertNotNull(getConsentObject(1));
        assertNotNull(getUserDocument().getXObject(USERS_CLASS_REFERENCE));
    }

    @Test
    void deleteConsentWithRelativeId() throws Exception
    {
        this.store.deleteConsent(this.user, "XWiki.User^XWiki.OIDC.ConsentClass[1]");

        assertNull(getConsentObject(1));
        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentOfAnotherUser() throws Exception
    {
        OIDCException exception = assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(this.otherUser, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]"));

        assertEquals("The consent [xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]] is not associated to the user"
            + " [xwiki:XWiki.OtherUser]", exception.getMessage());

        // Nothing was deleted
        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithObjectOfAnotherClass() throws Exception
    {
        OIDCException exception = assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(this.user, "xwiki:XWiki.User^XWiki.XWikiUsers[0]"));

        assertEquals("The object [xwiki:XWiki.User^XWiki.XWikiUsers[0]] is not a consent", exception.getMessage());

        // Nothing was deleted
        assertNotNull(getUserDocument().getXObject(USERS_CLASS_REFERENCE));
    }

    @Test
    void deleteConsentWithoutUser()
    {
        OIDCException exception = assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(null, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]"));

        assertEquals("A valid user reference is required to delete the consent"
            + " [xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]]", exception.getMessage());
    }

    @Test
    void deleteConsentWithUnknownUser()
    {
        UserReference unknownUser = mock(UserReference.class, "unknown");

        assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(unknownUser, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]"));
    }

    @Test
    void deleteConsentWithUnknownDocument() throws Exception
    {
        when(this.userReferenceSerializer.serialize(this.user))
            .thenReturn(new DocumentReference("xwiki", "XWiki", "NoSuchUser"));

        // Nothing to delete, but no error either
        this.store.deleteConsent(this.user, "xwiki:XWiki.NoSuchUser^XWiki.OIDC.ConsentClass[0]");

        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithUnknownConsent() throws Exception
    {
        // Nothing to delete, but no error either
        this.store.deleteConsent(this.user, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[42]");

        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithoutUserCheck() throws Exception
    {
        this.store.deleteConsent("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]");

        assertNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithoutUserCheckAndObjectOfAnotherClass() throws Exception
    {
        // Even when the user is not checked, only a consent can be deleted
        assertThrows(OIDCException.class, () -> this.store.deleteConsent("xwiki:XWiki.User^XWiki.XWikiUsers[0]"));

        assertNotNull(getUserDocument().getXObject(USERS_CLASS_REFERENCE));
    }
    @Test
    void createAccessToken() throws Exception
    {
        BaseObjectOIDCConsent consent = getConsent(1);

        XWikiBearerAccessToken accessToken = this.store.createAccessToken(consent);

        // A version 2 consent reference is <document reference>/<object number>
        assertEquals("xwiki:XWiki.User/1", accessToken.getConsentReference());
        assertEquals(accessToken.getConsentReference() + '/' + accessToken.getTokenValue(), accessToken.getValue());
        assertNull(accessToken.getExpiration());

        // The token is stored in the consent, as a version 2 token
        assertEquals(2, consent.getVersion());
        assertTrue(consent.isTokenValid(accessToken));
    }

    @Test
    void createAccessTokenWithExpiration() throws Exception
    {
        BaseObjectOIDCConsent consent = getConsent(0);
        Date expiration = new Date(42);

        XWikiBearerAccessToken accessToken = this.store.createAccessToken(consent, expiration);

        assertEquals("xwiki:XWiki.User/0", accessToken.getConsentReference());
        assertEquals(expiration, accessToken.getExpiration());
        assertEquals(expiration, consent.getAccessTokenExpiration());
    }

    @Test
    void getConsentFromAccessToken() throws Exception
    {
        XWikiBearerAccessToken accessToken = createAndSaveAccessToken(1, null);

        BaseObjectOIDCConsent consent = this.store.getConsent(accessToken);

        assertNotNull(consent);
        assertEquals("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[1]", consent.getId());
        assertEquals(USER_REFERENCE, consent.getUserReference());
    }

    @Test
    void getConsentFromAccessTokenWithVersion1Token() throws Exception
    {
        // A token created before the version 2: the consent reference is the reference of the xobject and the token
        // value is hashed without any salt
        XWikiBearerAccessToken accessToken =
            XWikiBearerAccessToken.create("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[1]");

        XWikiDocument userDocument = getUserDocument().clone();
        userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 1).set(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN,
            accessToken.getTokenValue(), this.oldcore.getXWikiContext());
        saveUserDocument(userDocument);

        BaseObjectOIDCConsent consent = this.store.getConsent(accessToken);

        assertNotNull(consent);
        assertEquals("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[1]", consent.getId());
    }

    @Test
    void getConsentFromAccessTokenCopiedToAnotherUser() throws Exception
    {
        XWikiBearerAccessToken accessToken = createAndSaveAccessToken(0, null);

        // Copy the consent as is in the document of another user, the way copying or renaming the document would
        XWikiContext xcontext = this.oldcore.getXWikiContext();
        XWikiDocument otherUserDocument = new XWikiDocument(OTHERUSER_REFERENCE);
        BaseObject otherConsentObject = otherUserDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        BaseObject consentObject = getConsentObject(0);
        otherConsentObject.setIntValue(BaseObjectOIDCConsent.FIELD_VERSION,
            consentObject.getIntValue(BaseObjectOIDCConsent.FIELD_VERSION));
        otherConsentObject.setStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN,
            consentObject.getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN));
        saveUserDocument(otherUserDocument);

        // The very same token value, but pointing to the copied consent
        XWikiBearerAccessToken copiedAccessToken = XWikiBearerAccessToken
            .parse("Bearer xwiki:XWiki.OtherUser/0/" + accessToken.getTokenValue());

        assertNull(this.store.getConsent(copiedAccessToken));

        // The token is still valid where it was created
        assertNotNull(this.store.getConsent(accessToken));
    }

    @Test
    void getConsentFromAccessTokenWithWrongTokenValue() throws Exception
    {
        createAndSaveAccessToken(0, null);

        assertNull(this.store.getConsent(XWikiBearerAccessToken.parse("Bearer xwiki:XWiki.User/0/wrongvalue")));
    }

    @Test
    void getConsentFromAccessTokenWithDisabledConsent() throws Exception
    {
        XWikiBearerAccessToken accessToken = createAndSaveAccessToken(0, null);

        XWikiDocument userDocument = getUserDocument().clone();
        new BaseObjectOIDCConsent("id", userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 0),
            this.oldcore.getXWikiContext()).setEnabled(false);
        saveUserDocument(userDocument);

        assertNull(this.store.getConsent(accessToken));
    }

    @Test
    void getConsentFromAccessTokenWithExpiredConsent() throws Exception
    {
        XWikiBearerAccessToken accessToken = createAndSaveAccessToken(0, new Date(42));

        assertNull(this.store.getConsent(accessToken));
    }

    @Test
    void getConsentFromAccessTokenWithNotExpiredConsent() throws Exception
    {
        XWikiBearerAccessToken accessToken =
            createAndSaveAccessToken(0, new Date(System.currentTimeMillis() + 3600000));

        assertNotNull(this.store.getConsent(accessToken));
    }

    @Test
    void getConsentFromAccessTokenWithEmptyTokenValue() throws Exception
    {
        // The consent does not have any token yet, so the stored token value is empty: an empty input token value
        // must not be considered as a match
        assertNull(this.store.getConsent(XWikiBearerAccessToken.parse("Bearer xwiki:XWiki.User/0/")));
    }

    @Test
    void getConsentFromAccessTokenWithEmptyTokenValueAndVersion1Consent() throws Exception
    {
        XWikiDocument userDocument = getUserDocument().clone();
        userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 1).set(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN, "",
            this.oldcore.getXWikiContext());
        saveUserDocument(userDocument);

        assertNull(this.store
            .getConsent(XWikiBearerAccessToken.parse("Bearer xwiki:XWiki.User^XWiki.OIDC.ConsentClass[1]/")));
    }

    @Test
    void getConsentFromAccessTokenWithUnknownDocument() throws Exception
    {
        assertNull(this.store.getConsent(XWikiBearerAccessToken.parse("Bearer xwiki:XWiki.NoSuchUser/0/value")));
    }

    @Test
    void getConsentFromAccessTokenWithUnknownConsent() throws Exception
    {
        assertNull(this.store.getConsent(XWikiBearerAccessToken.parse("Bearer xwiki:XWiki.User/42/value")));
    }

    @Test
    void createAndSaveAccessToken() throws Exception
    {
        XWikiBearerAccessToken accessToken = this.store.createAndSaveAccessToken(getConsent(0));

        assertEquals("xwiki:XWiki.User/0", accessToken.getConsentReference());

        // The token was saved, so it can be used to get the consent back
        BaseObjectOIDCConsent consent = this.store.getConsent(accessToken);

        assertNotNull(consent);
        assertEquals(2, consent.getVersion());
    }

    @Test
    void createUserConsent() throws Exception
    {
        XWikiDocument userDocument = getUserDocument().clone();

        BaseObjectOIDCConsent consent = this.store.createUserConsent(userDocument, null);

        // The consent is added to the existing ones
        assertEquals(2, consent.getNumber());
        assertEquals("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[2]", consent.getId());
        assertEquals(2, consent.getVersion());

        XWikiBearerAccessToken accessToken = consent.getAccessToken();
        assertNotNull(accessToken);
        assertEquals("xwiki:XWiki.User/2", accessToken.getConsentReference());
        assertTrue(consent.isTokenValid(accessToken));

        // A token created for another consent of the same user is not valid
        assertFalse(consent.isTokenValid(XWikiBearerAccessToken.parse(
            "Bearer xwiki:XWiki.User/2/" + this.store.createAccessToken(getConsent(0)).getTokenValue())));
    }

    @Test
    void getConsentFromAccessTokenWithASlashInTheDocumentName() throws Exception
    {
        // A "/" is a valid character in a document name, so only the last one separates the document reference from
        // the object number
        XWikiContext xcontext = this.oldcore.getXWikiContext();
        DocumentReference userReference = new DocumentReference("xwiki", "XWiki", "Us/er");
        XWikiDocument userDocument = new XWikiDocument(userReference);
        userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        saveUserDocument(userDocument);

        BaseObjectOIDCConsent consent = new BaseObjectOIDCConsent("id",
            this.oldcore.getSpyXWiki().getDocument(userReference, xcontext)
                .getXObject(BaseObjectOIDCConsent.REFERENCE, 0),
            xcontext);
        XWikiBearerAccessToken accessToken = this.store.createAccessToken(consent);
        saveUserDocument(consent.getOwnerDocument());

        assertEquals("xwiki:XWiki.Us/er/0", accessToken.getConsentReference());
        assertNotNull(this.store.getConsent(accessToken));
    }

}
