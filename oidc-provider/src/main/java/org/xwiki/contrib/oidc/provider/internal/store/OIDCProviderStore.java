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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.consent.internal.store.BaseObjectOIDCConsent;
import org.xwiki.contrib.oidc.consent.internal.store.OIDCConsentStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration.SubFormat;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.observation.ObservationManager;
import org.xwiki.user.UserReferenceSerializer;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Allow manipulating consents.
 * 
 * @version $Id$
 */
@Component(roles = OIDCProviderStore.class)
@Singleton
public class OIDCProviderStore
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Inject
    private EntityReferenceSerializer<String> referenceSerializer;

    @Inject
    private OIDCProviderConfiguration configuration;

    @Inject
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    @Inject
    private ObservationManager observation;

    @Inject
    private OIDCConsentStore consentStore;

    @Inject
    private Logger logger;

    private final Map<String, AuthorizationSession> authorizationSessionMap = new ConcurrentHashMap<>();

    /**
     * @return the authorizationSessionMap
     * @since 2.21.0
     */
    public Map<String, AuthorizationSession> getAuthorizationSessionMap()
    {
        return this.authorizationSessionMap;
    }

    /**
     * @param clientID the client ID
     * @param redirectURI the redirect URI
     * @param code the authorization code
     * @return the consent or {@code null} if not found
     * @throws XWikiException if an error occurs while retrieving the consent
     */
    public BaseObjectOIDCConsent getConsent(ClientID clientID, URI redirectURI, AuthorizationCode code)
        throws XWikiException
    {
        DocumentReference userReference = getUserReference(code);

        if (userReference == null) {
            return null;
        }

        return this.consentStore.getConsent(clientID, redirectURI, userReference);
    }

    /**
     * @param userDocument the user document
     * @return the URI of the user avatar or {@code null} if not found
     * @throws URISyntaxException if the avatar URL is not a valid URI
     */
    public URI getUserAvatarURI(XWikiDocument userDocument) throws URISyntaxException
    {
        String avatar = userDocument.getStringValue("avatar");

        return StringUtils.isEmpty(avatar) ? null
            : new URI(userDocument.getExternalAttachmentURL(avatar, "download", this.xcontextProvider.get()));
    }

    /**
     * @param userDocument the user document
     * @return the URI of the user profile or {@code null} if not found
     * @throws URISyntaxException if the profile URL is not a valid URI
     */
    public URI getUserProfileURI(XWikiDocument userDocument) throws URISyntaxException
    {
        return new URI(userDocument.getExternalURL("view", this.xcontextProvider.get()));
    }

    /**
     * @param code the authorization code
     * @return the reference of the user associated to the authorization code or {@code null} if not found
     */
    public DocumentReference getUserReference(AuthorizationCode code)
    {
        AuthorizationSession session = this.authorizationSessionMap.get(code.getValue());

        return session != null ? session.getUserReference() : null;
    }

    /**
     * @param code the authorization code
     * @return the nonce associated to the authorization code or {@code null} if not found
     * @since 1.24
     */
    public Nonce getNonce(AuthorizationCode code)
    {
        AuthorizationSession session = this.authorizationSessionMap.get(code.getValue());

        if (session != null) {
            return Nonce.parse(session.getNonce());
        }

        return null;
    }

    /**
     * @param userReference the reference of the user
     * @return the OIDC subject
     * @since 2.4.0
     */
    public Subject getSubject(DocumentReference userReference)
    {
        return new Subject(this.configuration.getSubMode() == SubFormat.LOCAL ? userReference.getName()
            : this.referenceSerializer.serialize(userReference));
    }

    /**
     * @param subject the OIDC subject
     * @return the reference of the user
     * @since 2.4.0
     */
    public DocumentReference getUserReference(Subject subject)
    {
        return this.resolver.resolve(subject.getValue());
    }

    /**
     * @param code the authorization code
     * @param userReference the reference of the user associated to the authorization code
     * @param nonce the nonce associated to the authorization code
     * @since 1.24
     */
    public void setAuthorizationCode(AuthorizationCode code, DocumentReference userReference, Nonce nonce)
    {
        if (code != null) {
            this.logger.debug("Remember authorization code [{}]", code);

            this.observation.notify(new AuthorizationCodeCreatedEvent(code),
                new AuthorizationSession(userReference, nonce));
        }
    }

    /**
     * @param code the authorization code to delete
     */
    public void deleteAuthorizationCode(AuthorizationCode code)
    {
        if (code != null) {
            this.logger.debug("Delete authorization code [{}]", code);

            this.observation.notify(new AuthorizationCodeDeletedEvent(code), null);
        }
    }
}
