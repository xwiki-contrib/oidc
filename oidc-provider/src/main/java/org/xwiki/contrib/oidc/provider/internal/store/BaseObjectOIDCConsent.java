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
package org.xwiki.contrib.oidc.provider.internal.store;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.contrib.oidc.OIDCConsent;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseObjectReference;
import com.xpn.xwiki.objects.classes.PasswordClass;

/**
 * {@link BaseObject} based implementation of {@link OIDCConsent}.
 * 
 * @version $Id$
 * @since 2.13.0
 */
public class BaseObjectOIDCConsent implements OIDCConsent
{
    /**
     * The reference of the class as String.
     */
    public static final String REFERENCE_STRING = "XWiki.OIDC.ConsentClass";

    /**
     * The reference of the class.
     */
    public static final LocalDocumentReference REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "ConsentClass");

    /**
     * The field containing the OIDC client ID.
     */
    public static final String FIELD_CLIENTID = "clientId";

    /**
     * The field containing the OIDC redirect URI.
     */
    public static final String FIELD_REDIRECTURI = "redirectURI";

    /**
     * The field containing the encrypted OIDC access token.
     */
    public static final String FIELD_ACCESSTOKEN = "accessToken";

    /**
     * The field containing the OIDC access token expiration date.
     */
    public static final String FIELD_ACCESSTOKEN_EXPIRE = "accessToken_expire";

    /**
     * The field containing the OIDC claims.
     */
    public static final String FIELD_CLAIMS = "claims";

    /**
     * The field indicating of the consent is enabled or not.
     */
    public static final String FIELD_ENABLED = "enabled";

    private ClaimsSetRequest claims;

    private final String id;

    private final BaseObject xobject;

    private final XWikiContext xcontext;

    private XWikiBearerAccessToken accessToken;

    /**
     * @param id the identifier of the consent
     * @param xobject the actual XWiki object
     * @param xcontext the XWiki context
     */
    public BaseObjectOIDCConsent(String id, BaseObject xobject, XWikiContext xcontext)
    {
        this.id = id;
        this.xobject = xobject;
        this.xcontext = xcontext;
    }

    /**
     * @return the owner document of this element.
     */
    public XWikiDocument getOwnerDocument()
    {
        return this.xobject.getOwnerDocument();
    }

    /**
     * @return the reference of the ower document
     */
    public DocumentReference getDocumentReference()
    {
        return this.xobject.getDocumentReference();
    }

    /**
     * @return the reference of the object
     */
    public BaseObjectReference getReference()
    {
        return this.xobject.getReference();
    }

    @Override
    public String getId()
    {
        return this.id;
    }

    @Override
    public String getClientID()
    {
        String str = this.xobject.getStringValue(FIELD_CLIENTID);

        return StringUtils.isNotEmpty(str) ? str : null;
    }

    /**
     * @param clientID the OIDC client ID
     */
    public void setClientID(ClientID clientID)
    {
        this.xobject.setStringValue(FIELD_CLIENTID, clientID != null ? clientID.getValue() : "");
    }

    @Override
    public URI getRedirectURI()
    {
        String str = this.xobject.getStringValue(FIELD_REDIRECTURI);

        if (StringUtils.isNotEmpty(str)) {
            try {
                return new URI(str);
            } catch (URISyntaxException e) {
                // Should never happen
                // TODO: log error
            }
        }

        return null;
    }

    /**
     * @param uri the OIDC redirect
     */
    public void setRedirectURI(URI uri)
    {
        this.xobject.setStringValue(FIELD_REDIRECTURI, uri.toString());
    }

    @Override
    public String getAccessTokenValue()
    {
        return this.accessToken != null ? this.accessToken.getValue() : null;
    }

    /**
     * @return the clear access token
     */
    public XWikiBearerAccessToken getAccessToken()
    {
        return this.accessToken;
    }

    /**
     * @param accessToken the token to encrypt and store
     */
    public void setAccessToken(XWikiBearerAccessToken accessToken)
    {
        // Remember the clear access token
        this.accessToken = accessToken;

        if (accessToken == null) {
            // Reset the access token value
            this.xobject.removeField(FIELD_ACCESSTOKEN);

            // Reset the expiration date
            this.xobject.removeField(FIELD_ACCESSTOKEN_EXPIRE);
        } else {
            // Encrypt and set the token value
            this.xobject.set(FIELD_ACCESSTOKEN, accessToken.getRandom(), this.xcontext);

            // Set the expiration date
            setAccessTokenExpiration(accessToken.getExpiration());
        }
    }

    /**
     * @param accessToken the token to validate
     * @return true if the passed token matches the stored one, false otherwise
     */
    public boolean isTokenValid(XWikiBearerAccessToken accessToken)
    {
        String stored = this.xobject.getStringValue(FIELD_ACCESSTOKEN);

        return new PasswordClass().getEquivalentPassword(stored, accessToken.getRandom()).equals(stored);
    }

    @Override
    public Date getAccessTokenExpiration()
    {
        return this.xobject.getDateValue(FIELD_ACCESSTOKEN_EXPIRE);
    }

    /**
     * @param lifetime the token lifetime in seconds, 0 for unlimited
     */
    public void setAccessTokenLifetime(long lifetime)
    {
        if (lifetime > 0) {
            setAccessTokenExpiration(Date.from(Instant.now().plusSeconds(lifetime)));
        } else {
            setAccessTokenExpiration(null);
        }
    }

    /**
     * @param expiration the token expiration date, null for unlimited
     */
    public void setAccessTokenExpiration(Date expiration)
    {
        this.xobject.setDateValue(FIELD_ACCESSTOKEN_EXPIRE, expiration);
    }

    @Override
    public boolean isEnabled()
    {
        int allow = this.xobject.getIntValue(FIELD_ENABLED, 1);

        return allow == 1;
    }

    /**
     * @param enabled true of the consent is enabled
     */
    public void setEnabled(boolean enabled)
    {
        this.xobject.setIntValue(FIELD_ENABLED, enabled ? 1 : 0);
    }

    /**
     * @return the document reference of the user
     */
    public DocumentReference getUserReference()
    {
        return this.xobject.getDocumentReference();
    }

    /**
     * @return the OIDC claims
     * @throws ParseException when failing to parse the claims
     */
    public ClaimsSetRequest getClaims() throws ParseException
    {
        if (this.claims == null) {
            String claimsString = this.xobject.getLargeStringValue(FIELD_CLAIMS);

            if (StringUtils.isNotEmpty(claimsString)) {
                this.claims = ClaimsSetRequest.parse(claimsString);
            }
        }

        return this.claims;
    }

    /**
     * @param claims the OIDC claims
     */
    public void setClaims(ClaimsSetRequest claims)
    {
        this.claims = claims;

        if (claims != null) {
            this.xobject.setLargeStringValue(FIELD_CLAIMS, claims.toString());
        } else {
            this.xobject.removeField(FIELD_CLAIMS);
        }
    }

    /**
     * @return if the consent has been modified
     */
    public boolean isModified()
    {
        return this.xobject.getOwnerDocument().isMetaDataDirty();
    }
}
