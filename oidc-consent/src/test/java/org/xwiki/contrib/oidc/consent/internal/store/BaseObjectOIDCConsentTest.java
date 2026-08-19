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

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validate {@link BaseObjectOIDCConsent}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class BaseObjectOIDCConsentTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    // Used when an xobject is serialized as part of an error message
    @MockComponent
    private XWikiDocumentFilterUtils filterUtils;

    @InjectMockComponents
    private OIDCConsentClassDocumentInitializer classInitializer;

    private XWikiDocument userDocument;

    private BaseObject xobject;

    private BaseObjectOIDCConsent consent;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        // Make sure the consent class exist since the consent needs it to encrypt the access token
        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);

        this.userDocument = new XWikiDocument(USER_REFERENCE);
        this.xobject = this.userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);

        this.consent = new BaseObjectOIDCConsent("id", this.xobject, xcontext);
    }

    private XWikiBearerAccessToken createAccessToken()
    {
        return XWikiBearerAccessToken.create("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]");
    }

    @Test
    void constructorWithWrongObject()
    {
        BaseObject wrongObject = new BaseObject();
        wrongObject.setXClassReference(new LocalDocumentReference("XWiki", "XWikiUsers"));
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> new BaseObjectOIDCConsent("id", wrongObject, xcontext));

        assertTrue(exception.getMessage().endsWith("is not a consent object"), exception.getMessage());
    }

    @Test
    void getId()
    {
        assertEquals("id", this.consent.getId());
    }

    @Test
    void getOwnerDocumentAndReferences()
    {
        assertSame(this.userDocument, this.consent.getOwnerDocument());
        assertEquals(USER_REFERENCE, this.consent.getDocumentReference());
        assertEquals(USER_REFERENCE, this.consent.getUserReference());
        assertEquals(this.xobject.getReference(), this.consent.getReference());
    }

    @Test
    void clientID()
    {
        assertNull(this.consent.getClientID());

        this.consent.setClientID(new ClientID("clientid"));

        assertEquals("clientid", this.consent.getClientID());
        assertEquals("clientid", this.xobject.getStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID));

        this.consent.setClientID(null);

        assertNull(this.consent.getClientID());
        assertEquals("", this.xobject.getStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID));
    }

    @Test
    void redirectURI()
    {
        assertNull(this.consent.getRedirectURI());

        this.consent.setRedirectURI(URI.create("http://host/redirect"));

        assertEquals(URI.create("http://host/redirect"), this.consent.getRedirectURI());
        assertEquals("http://host/redirect", this.xobject.getStringValue(BaseObjectOIDCConsent.FIELD_REDIRECTURI));
    }

    @Test
    void getRedirectURIWithInvalidStoredValue()
    {
        this.xobject.setStringValue(BaseObjectOIDCConsent.FIELD_REDIRECTURI, "http://host/invalid redirect");

        assertNull(this.consent.getRedirectURI());
    }

    @Test
    void accessToken()
    {
        assertNull(this.consent.getAccessToken());
        assertNull(this.consent.getAccessTokenValue());
        assertNull(this.consent.getAccessTokenExpiration());

        XWikiBearerAccessToken accessToken = createAccessToken();
        Date expiration = new Date(42);
        accessToken = XWikiBearerAccessToken.create(accessToken.getDocumentObjectReference(), expiration);

        this.consent.setAccessToken(accessToken);

        assertSame(accessToken, this.consent.getAccessToken());
        assertEquals(accessToken.getValue(), this.consent.getAccessTokenValue());
        assertEquals(expiration, this.consent.getAccessTokenExpiration());

        // The token is not stored in clear
        String stored = this.xobject.getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN);
        assertTrue(stored.startsWith("hash:"), stored);
        assertFalse(stored.contains(accessToken.getRandom()), stored);
    }

    @Test
    void setAccessTokenWithNull()
    {
        this.consent.setAccessToken(createAccessToken());
        this.consent.setAccessTokenExpiration(new Date(42));

        this.consent.setAccessToken(null);

        assertNull(this.consent.getAccessToken());
        assertNull(this.consent.getAccessTokenValue());
        assertNull(this.consent.getAccessTokenExpiration());
        assertEquals("", this.xobject.getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN));
    }

    @Test
    void isTokenValid()
    {
        XWikiBearerAccessToken accessToken = createAccessToken();

        // Nothing stored yet
        assertFalse(this.consent.isTokenValid(accessToken));

        this.consent.setAccessToken(accessToken);

        assertTrue(this.consent.isTokenValid(accessToken));
        assertFalse(this.consent.isTokenValid(createAccessToken()));
    }

    @Test
    void accessTokenExpiration()
    {
        this.consent.setAccessTokenExpiration(new Date(42));

        assertEquals(new Date(42), this.consent.getAccessTokenExpiration());

        this.consent.setAccessTokenExpiration(null);

        assertNull(this.consent.getAccessTokenExpiration());
    }

    @Test
    void setAccessTokenLifetime()
    {
        Date before = new Date();

        this.consent.setAccessTokenLifetime(3600);

        Date expiration = this.consent.getAccessTokenExpiration();
        assertNotNull(expiration);
        assertTrue(expiration.getTime() >= before.getTime() + 3600000, "Unexpected expiration date " + expiration);

        // A lifetime of 0 means unlimited
        this.consent.setAccessTokenLifetime(0);

        assertNull(this.consent.getAccessTokenExpiration());
    }

    @Test
    void enabled()
    {
        // A consent is enabled by default
        assertTrue(this.consent.isEnabled());

        this.consent.setEnabled(false);

        assertFalse(this.consent.isEnabled());
        assertEquals(0, this.xobject.getIntValue(BaseObjectOIDCConsent.FIELD_ENABLED));

        this.consent.setEnabled(true);

        assertTrue(this.consent.isEnabled());
        assertEquals(1, this.xobject.getIntValue(BaseObjectOIDCConsent.FIELD_ENABLED));
    }

    @Test
    void claims() throws ParseException
    {
        assertNull(this.consent.getClaims());

        ClaimsSetRequest claims = new ClaimsSetRequest().add("email");

        this.consent.setClaims(claims);

        assertSame(claims, this.consent.getClaims());
        assertEquals(claims.toString(), this.xobject.getLargeStringValue(BaseObjectOIDCConsent.FIELD_CLAIMS));

        this.consent.setClaims(null);

        assertNull(this.consent.getClaims());
        assertEquals("", this.xobject.getLargeStringValue(BaseObjectOIDCConsent.FIELD_CLAIMS));
    }

    @Test
    void getClaimsFromStoredValue() throws ParseException
    {
        this.xobject.setLargeStringValue(BaseObjectOIDCConsent.FIELD_CLAIMS,
            new ClaimsSetRequest().add("email").toString());

        ClaimsSetRequest claims = this.consent.getClaims();

        assertNotNull(claims);
        assertEquals(Collections.singleton("email"), claims.getClaimNames(false));

        // The parsed claims are cached
        assertSame(claims, this.consent.getClaims());
    }

    @Test
    void isModified()
    {
        this.userDocument.setMetaDataDirty(false);

        assertFalse(this.consent.isModified());

        this.consent.setEnabled(false);

        assertTrue(this.consent.isModified());
    }
}
