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

import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.xwiki.contrib.oidc.OIDCConsent;
import org.xwiki.model.reference.LocalDocumentReference;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.PasswordClass;

/**
 * {@link BaseObject} based implementation of {@link OIDCConsent}.
 * 
 * @version $Id$
 * @since 2.21.0
 */
public class BaseObjectOIDCClient
{
    /**
     * The name of the xclass.
     */
    public static final String CLASS_NAME = "ClientClass";

    /**
     * The local reference of the client xclass.
     */
    public static final LocalDocumentReference REFERENCE =
        new LocalDocumentReference(CLASS_NAME, OIDCProviderStore.REFERENCE_SPACE);

    /**
     * The local reference of the client xclass as String.
     */
    public static final String REFERENCE_STRING = OIDCProviderStore.REFERENCE_PREFIX + CLASS_NAME;

    /**
     * The field containing the OIDC client ID.
     */
    public static final String FIELD_ID = "id";

    /**
     * The field containing the OIDC client secret.
     */
    public static final String FIELD_SECRET = "secret";

    /**
     * The field containing the OIDC client redirect URI.
     */
    public static final String FIELD_REDIRECT_URIS = "redirectURIs";

    /**
     * The field containing the OIDC client back-channel logout URI.
     */
    public static final String FIELD_BACKCHANNEL_LOGOUT_URI = "logoutURI";

    /**
     * The field indicating of the client is enabled.
     */
    public static final String FIELD_ENABLED = "enabled";

    private BaseObject xobject;

    private XWikiContext xcontext;

    /**
     * @param xobject the actual XWiki object
     * @param xcontext the XWiki context
     */
    public BaseObjectOIDCClient(BaseObject xobject, XWikiContext xcontext)
    {
        this.xobject = xobject;
        this.xcontext = xcontext;
    }

    /**
     * @param xobject the xobject to check
     * @return true if the client is enabled, false otherwise
     */
    public static boolean isEnabled(BaseObject xobject)
    {
        int enabled = xobject.getIntValue(BaseObjectOIDCClient.FIELD_ENABLED, 1);

        return enabled != 0;
    }

    /**
     * @param xobject the xobject to check
     * @return the client ID, or null if not set
     */
    public static String getClientID(BaseObject xobject)
    {
        String str = xobject.getStringValue(BaseObjectOIDCClient.FIELD_ID);

        return StringUtils.isNotEmpty(str) ? str : null;
    }

    /**
     * @return the client ID, or null if not set
     */
    public String getClientID()
    {
        return getClientID(this.xobject);
    }

    /**
     * Check if the provided client authentication is valid for this client.
     * 
     * @param clientAuthentication the client authentication to check
     * @throws InvalidClientException if the provided password is invalid
     */
    public void checkSecret(ClientAuthentication clientAuthentication) throws InvalidClientException
    {
        String storedSecret = this.xobject.getStringValue(BaseObjectOIDCClient.FIELD_SECRET);

        // Empty seccret means that no secret is required, so we don't check it
        if (StringUtils.isNotEmpty(storedSecret)) {
            if (clientAuthentication == null) {
                throw InvalidClientException.BAD_SECRET;
            } else if (clientAuthentication instanceof PlainClientSecret) {
                checkSecretPlain(storedSecret, clientAuthentication);
            } else {
                // TODO: add support for other types:
                // - ClientSecretJWT
                // - PrivateKeyJWT
                // - PKITLSClientAuthentication
                // - SelfSignedTLSClientAuthentication
                throw new RuntimeException("Unsupported client authentication: " + clientAuthentication.getMethod());
            }
        }
    }

    private void checkSecretPlain(String storedSecret, ClientAuthentication clientAuthentication)
        throws InvalidClientException
    {
        PlainClientSecret plainAuth = (PlainClientSecret) clientAuthentication;
        String secret = plainAuth.getClientSecret().getValue();

        PasswordClass passwordClass =
            (PasswordClass) this.xobject.getXClass(this.xcontext).getField(BaseObjectOIDCClient.FIELD_SECRET);
        if (!passwordClass.getEquivalentPassword(storedSecret, secret).equals(storedSecret)) {
            throw InvalidClientException.BAD_SECRET;
        }
    }

    /**
     * Check if the provided redirect URI is valid for this client.
     * 
     * @param redirectURI the redirect URI to check
     * @throws InvalidClientException if the provided redirect URI is invalid
     */
    public void checkRedirectURI(String redirectURI) throws InvalidClientException
    {
        if (!isRedirectURIValid(redirectURI)) {
            throw new InvalidClientException("Bad client redirect URI");
        }
    }

    /**
     * @param uri the redirect URI to check
     * @return true if the provided redirect URI is valid for this client, false otherwise
     */
    public boolean isRedirectURIValid(String uri)
    {
        // Get stored redirect URIs
        List<String> storedURIs = this.xobject.getListValue(BaseObjectOIDCClient.FIELD_REDIRECT_URIS);

        // If no redirect URI is stored, then any redirect URI is valid
        if (CollectionUtils.isEmpty(storedURIs)) {
            return true;
        }

        // Check stored redirect URIs
        for (String storedURI : storedURIs) {
            if (StringUtils.equals(storedURI, uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return true if the client has a secret and it should be validated, false otherwise
     */
    public boolean shouldValidateSecret()
    {
        String storedSecret = this.xobject.getStringValue(BaseObjectOIDCClient.FIELD_SECRET);

        return StringUtils.isNotEmpty(storedSecret);
    }

    /**
     * @return true if the client has at least one redirect URI and it should be validated, false otherwise
     */
    public boolean shouldValidateRedirectURI()
    {
        List<String> storedURIs = this.xobject.getListValue(BaseObjectOIDCClient.FIELD_REDIRECT_URIS);

        return CollectionUtils.isNotEmpty(storedURIs);
    }

    /**
     * @return true if the client should be taken into account, false otherwise
     */
    public boolean isEnabled()
    {
        return BaseObjectOIDCClient.isEnabled(this.xobject);
    }

    /**
     * @return the xobject
     */
    public BaseObject getXobject()
    {
        return this.xobject;
    }
}
