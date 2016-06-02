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

import org.apache.commons.lang3.StringUtils;
import org.xwiki.model.reference.DocumentReference;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.xpn.xwiki.objects.BaseObject;

public class OIDCConsent extends BaseObject
{
    public static final String FIELD_CLIENTID = "clientId";

    public static final String FIELD_REDIRECTURI = "redirectURI";

    public static final String FIELD_AUTHORIZATIONCODE = "authorizationCode";

    public static final String FIELD_ACCESSTOKEN = "accessToken";

    /**
     * @since 1.2
     */
    public static final String FIELD_CLAIMS = "claims";

    public static final String FIELD_ALLOW = "allow";

    public ClientID getClientID()
    {
        String str = getStringValue(FIELD_CLIENTID);

        return StringUtils.isNotEmpty(str) ? new ClientID(str) : null;
    }

    public void setClientID(ClientID clientID)
    {
        setStringValue(FIELD_CLIENTID, clientID.getValue());
    }

    public URI getRedirectURI()
    {
        String str = getStringValue(FIELD_REDIRECTURI);

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
        setStringValue(FIELD_REDIRECTURI, uri.toString());
    }

    public AuthorizationCode getAuthorizationCode()
    {
        String str = getStringValue(FIELD_AUTHORIZATIONCODE);

        return StringUtils.isNotEmpty(str) ? new AuthorizationCode(str) : null;
    }

    public void setAuthorizationCode(AuthorizationCode code)
    {
        if (code == null) {
            removeField(FIELD_AUTHORIZATIONCODE);
        } else {
            setStringValue(FIELD_AUTHORIZATIONCODE, code.getValue());
        }
    }

    public AccessToken getAccessToken()
    {
        String str = getStringValue(FIELD_ACCESSTOKEN);

        return StringUtils.isNotEmpty(str) ? new BearerAccessToken(str) : null;
    }

    public void setAccessToken(AccessToken accessToken)
    {
        if (accessToken == null) {
            removeField(FIELD_ACCESSTOKEN);
        } else {
            setStringValue(FIELD_ACCESSTOKEN, accessToken.getValue());
        }
    }

    public boolean isAllowed()
    {
        int allow = getIntValue(FIELD_ALLOW, 1);

        return allow == 1;
    }

    public void setAllowed(boolean allowed)
    {
        setIntValue(FIELD_ALLOW, allowed ? 1 : 0);
    }

    public DocumentReference getUserReference()
    {
        return getDocumentReference();
    }

    /**
     * @since 1.2
     */
    public ClaimsRequest getClaims() throws ParseException
    {
        String claims = getLargeStringValue(FIELD_CLAIMS);

        if (StringUtils.isNotEmpty(claims)) {
            return ClaimsRequest.parse(claims);
        }

        return null;
    }

    /**
     * @since 1.2
     */
    public void setClaims(ClaimsRequest claims)
    {
        if (claims != null) {
            setLargeStringValue(FIELD_CLAIMS, claims.toString());
        } else {
            removeField(FIELD_CLAIMS);
        }
    }
}
