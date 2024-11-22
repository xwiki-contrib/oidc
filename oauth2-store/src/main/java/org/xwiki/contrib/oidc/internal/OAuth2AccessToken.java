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
package org.xwiki.contrib.oidc.internal;

import java.util.Arrays;

import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.model.reference.LocalDocumentReference;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.objects.BaseObject;

/**
 * A helper wrapping a BaseObject to make easier to manipulate access tokens.
 *
 * @version $Id$
 * @since 1.25
 */
public class OAuth2AccessToken
{
    /**
     * The full name of the access token class.
     */
    public static final String CLASS_FULLNAME = "XWiki.OAuth2.AccessTokenClass";

    /**
     * The local reference of the access token class.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OAuth2"), "AccessTokenClass");

    /**
     * The name of the client configuration to which this token relates to.
     */
    public static final String FIELD_CLIENT_CONFIGURATION_NAME = "clientConfigurationName";

    /**
     * The token value.
     */
    public static final String FIELD_VALUE = "value";

    /**
     * The token type.
     */
    public static final String FIELD_TYPE = "type";

    /**
     * The token scope.
     */
    public static final String FIELD_SCOPE = "scope";

    /**
     * The token lifetime.
     */
    public static final String FIELD_EXPIRES_AT = "expiresAt";

    private final BaseObject xobject;

    /**
     * @param xobject the actual XWiki object
     */
    public OAuth2AccessToken(BaseObject xobject)
    {
        this.xobject = xobject;
    }

    /**
     * @return the name of the client configuration this token relates to
     */
    public String getClientConfigurationName()
    {
        return this.xobject.getStringValue(FIELD_CLIENT_CONFIGURATION_NAME);
    }

    /**
     * @param clientConfigurationName the name of the client configuration this token relates to
     */
    public void setClientConfigurationName(String clientConfigurationName)
    {
        this.xobject.setStringValue(FIELD_CLIENT_CONFIGURATION_NAME, clientConfigurationName);
    }

    /**
     * @return the token value
     */
    public String getValue()
    {
        return this.xobject.getStringValue(FIELD_VALUE);
    }

    /**
     * @param value the token value
     */
    public void setValue(String value)
    {
        this.xobject.setStringValue(FIELD_VALUE, value);
    }

    /**
     * @return the token type
     */
    public AccessTokenType getType()
    {
        return new AccessTokenType(this.xobject.getStringValue(FIELD_TYPE));
    }

    /**
     * @param type the token type
     */
    public void setType(AccessTokenType type)
    {
        this.xobject.setStringValue(FIELD_TYPE, type.getValue());
    }

    /**
     * @return the token expiration timestamp
     */
    public long getExpiresAt()
    {
        return this.xobject.getLongValue(FIELD_EXPIRES_AT);
    }

    /**
     * @param expiresAt the token expiration timestamp
     */
    public void setExpiresAt(long expiresAt)
    {
        this.xobject.setLongValue(FIELD_EXPIRES_AT, expiresAt);
    }

    /**
     * @return the token scopes
     */
    public Scope getScope()
    {
        Scope scope = new Scope();
        for (Object value : this.xobject.getListValue(FIELD_SCOPE)) {
            scope.add((String) value);
        }
        return scope;
    }

    /**
     * @param scope the token scopes
     */
    public void setScope(Scope scope)
    {
        this.xobject.setStringListValue(FIELD_SCOPE, scope.toStringList());
    }

    /**
     * @param accessToken the access token to store
     */
    public void fromAccessToken(AccessToken accessToken)
    {

        setValue(accessToken.getValue());
        setType(accessToken.getType());
        setExpiresAt(System.currentTimeMillis() + (accessToken.getLifetime() * 1000));
        setScope(accessToken.getScope());
    }

    /**
     * @return the access token corresponding to the stored token
     * @throws OAuth2Exception if the access token type is not supported
     */
    public AccessToken toAccessToken() throws OAuth2Exception
    {
        // For now, only bearer access tokens are supported.
        if (!AccessTokenType.BEARER.equals(getType())) {
            throw new OAuth2Exception(
                String.format("Failed to convert access token : type [%s] is unsupported.", getType().toString()));
        } else {
            long lifetime = Math.min(((getExpiresAt() - System.currentTimeMillis()) / 1000), 0);
            return new BearerAccessToken(getValue(), lifetime, getScope());
        }
    }

}
