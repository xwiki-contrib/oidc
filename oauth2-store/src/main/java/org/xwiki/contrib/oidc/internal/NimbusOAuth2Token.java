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
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.OAuth2Token;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.model.reference.ObjectReference;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.objects.BaseObject;

/**
 * An OAuth2 token stored in XWiki.
 *
 * @version $Id$
 * @since 2.16.0
 */
public class NimbusOAuth2Token implements OAuth2Token
{
    /**
     * The full name of the access token class.
     */
    public static final String CLASS_FULLNAME = "XWiki.OAuth2.TokenClass";

    /**
     * The local reference of the access token class.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OAuth2"), "TokenClass");

    /**
     * The name of the client configuration to which this token relates to.
     */
    public static final String FIELD_CLIENT_CONFIGURATION_NAME = "clientConfigurationName";

    /**
     * The access token.
     */
    public static final String FIELD_ACCESS_TOKEN = "accessToken";

    /**
     * The refresh token.
     */
    public static final String FIELD_REFRESH_TOKEN = "refreshToken";

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

    private OIDCClientConfiguration configuration;

    private ObjectReference reference;

    private String accessToken;

    private String refreshToken;

    private AccessTokenType type;

    private long expiresAt;

    private Scope scope;

    /**
     * Create a new token based on a stored object.
     *
     * @param configuration the token configuration
     * @param xobject the actual XWiki object
     */
    public NimbusOAuth2Token(OIDCClientConfiguration configuration, BaseObject xobject)
    {
        this.configuration = configuration;
        this.reference = xobject.getReference();
        this.accessToken = xobject.getStringValue(FIELD_ACCESS_TOKEN);
        this.refreshToken = xobject.getStringValue(FIELD_REFRESH_TOKEN);
        this.type = new AccessTokenType(xobject.getStringValue(FIELD_TYPE));
        this.expiresAt = xobject.getLongValue(FIELD_EXPIRES_AT);
        this.scope = new Scope();
        this.scope.addAll(xobject.getListValue(FIELD_SCOPE));
    }

    /**
     * Create a new OAuth2 token from Nimbus objects.
     *
     * @param configuration the token configuration
     * @param reference the token reference
     * @param accessToken the access token
     * @param refreshToken the refresh token
     */
    public NimbusOAuth2Token(OIDCClientConfiguration configuration, ObjectReference reference, AccessToken accessToken,
        RefreshToken refreshToken)
    {
        this.configuration = configuration;
        this.reference = reference;
        fromAccessToken(accessToken);
        fromRefreshToken(refreshToken);
    }

    @Override
    public OIDCClientConfiguration getConfiguration()
    {
        return configuration;
    }

    /**
     * @param configuration the token configuration
     */
    public void setConfiguration(OIDCClientConfiguration configuration)
    {
        this.configuration = configuration;
    }

    @Override
    public ObjectReference getReference()
    {
        return reference;
    }

    /**
     * @param reference the token object reference
     */
    private void setReference(ObjectReference reference)
    {
        this.reference = reference;
    }

    @Override
    public String getAccessToken()
    {
        return accessToken;
    }

    /**
     * @param accessToken the access token
     */
    public void setAccessToken(String accessToken)
    {
        this.accessToken = accessToken;
    }

    @Override
    public String getRefreshToken()
    {
        return refreshToken;
    }

    /**
     * @param refreshToken the refresh token
     */
    public void setRefreshToken(String refreshToken)
    {
        this.refreshToken = refreshToken;
    }

    @Override
    public String getType()
    {
        return type.toString();
    }

    /**
     * @param type the token type
     */
    public void setType(AccessTokenType type)
    {
        this.type = type;
    }

    @Override
    public long getExpiresAt()
    {
        return expiresAt;
    }

    /**
     * @param expiresAt the token expiration timestamp
     */
    public void setExpiresAt(long expiresAt)
    {
        this.expiresAt = expiresAt;
    }

    @Override
    public List<String> getScopes()
    {
        return scope.toStringList();
    }

    /**
     * @param scope the token scopes
     */
    public void setScope(Scope scope)
    {
        this.scope = scope;
    }

    /**
     * @param accessToken the access token to store
     */
    public void fromAccessToken(AccessToken accessToken)
    {
        setAccessToken(accessToken.getValue());
        setType(accessToken.getType());
        setExpiresAt(System.currentTimeMillis() + (accessToken.getLifetime() * 1000));
        setScope(accessToken.getScope());
    }

    /**
     * @param refreshToken the refresh token to store
     */
    public void fromRefreshToken(RefreshToken refreshToken)
    {
        if (refreshToken != null && StringUtils.isNotBlank(refreshToken.getValue())) {
            setRefreshToken(refreshToken.getValue());
        }
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
            return new BearerAccessToken(getAccessToken(), lifetime, Scope.parse(getScopes()));
        }
    }

    /**
     * @return the refresh token corresponding to the stored token, or null if the token doesn't exist
     */
    public RefreshToken toRefreshToken()
    {
        return StringUtils.isBlank(getRefreshToken()) ? null : new RefreshToken(getRefreshToken());
    }

    /**
     * Update the given xobject with the token properties.
     *
     * @param xobject the xobject to update
     */
    public void applyTo(BaseObject xobject)
    {
        xobject.setStringValue(FIELD_CLIENT_CONFIGURATION_NAME, configuration.getConfigurationName());
        xobject.setStringValue(FIELD_ACCESS_TOKEN, accessToken);
        xobject.setStringValue(FIELD_REFRESH_TOKEN, refreshToken);
        xobject.setStringValue(FIELD_TYPE, type.toString());
        xobject.setLongValue(FIELD_EXPIRES_AT, expiresAt);
        xobject.setStringListValue(FIELD_SCOPE, scope.toStringList());
    }
}
