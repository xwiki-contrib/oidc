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
import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
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

public class OIDCConsent
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

    public static final String FIELD_CLIENTID = "clientId";

    public static final String FIELD_REDIRECTURI = "redirectURI";

    public static final String FIELD_ACCESSTOKEN = "accessToken";

    /**
     * @since 1.2
     */
    public static final String FIELD_CLAIMS = "claims";

    public static final String FIELD_ALLOW = "allow";

    private ClaimsSetRequest claims;

    private final BaseObject xobject;

    /**
     * @param xobject the actual XWiki object
     */
    public OIDCConsent(BaseObject xobject)
    {
        this.xobject = xobject;
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

    public ClientID getClientID()
    {
        String str = this.xobject.getStringValue(FIELD_CLIENTID);

        return StringUtils.isNotEmpty(str) ? new ClientID(str) : null;
    }

    public void setClientID(ClientID clientID)
    {
        this.xobject.setStringValue(FIELD_CLIENTID, clientID.getValue());
    }

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

    public void setRedirectURI(URI uri)
    {
        this.xobject.setStringValue(FIELD_REDIRECTURI, uri.toString());
    }

    public String getAccessToken()
    {
        String str = this.xobject.getStringValue(FIELD_ACCESSTOKEN);

        return StringUtils.isNotEmpty(str) ? str : null;
    }

    public void setAccessToken(String accessToken, XWikiContext xcontext)
    {
        if (accessToken == null) {
            this.xobject.removeField(FIELD_ACCESSTOKEN);
        } else {
            this.xobject.set(FIELD_ACCESSTOKEN, accessToken, xcontext);
        }
    }

    public boolean isAllowed()
    {
        int allow = this.xobject.getIntValue(FIELD_ALLOW, 1);

        return allow == 1;
    }

    public void setAllowed(boolean allowed)
    {
        this.xobject.setIntValue(FIELD_ALLOW, allowed ? 1 : 0);
    }

    public DocumentReference getUserReference()
    {
        return this.xobject.getDocumentReference();
    }

    /**
     * @since 1.25
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
     * @since 1.25
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
}
