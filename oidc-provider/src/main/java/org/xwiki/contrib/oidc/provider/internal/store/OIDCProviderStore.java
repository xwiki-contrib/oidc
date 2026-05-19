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
import java.util.List;
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
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.user.UserReferenceSerializer;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Allow manipulating consents.
 * 
 * @version $Id$
 */
@Component(roles = OIDCProviderStore.class)
@Singleton
public class OIDCProviderStore
{
    /**
     * @since 2.21.0
     */
    public static final EntityReference REFERENCE_SPACE = new EntityReference("Provider", EntityType.SPACE,
        new EntityReference("OIDC", EntityType.SPACE, XWiki.SYSTEM_SPACE_REFERENCE));

    /**
     * @since 2.21.0
     */
    public static final String REFERENCE_PREFIX = "XWiki.OIDC.Provider.";

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

    // Clients

    private XWikiDocument getClientsDocument() throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        WikiReference currentWiki = xcontext.getWikiReference();
        try {
            // Clients are located on the main wiki
            xcontext.setWikiId(xcontext.getMainXWiki());

            // Load the user document containing the clients configurations
            return xcontext.getWiki().getDocument(OIDCProviderClientsInitializer.REFERENCE, xcontext);
        } finally {
            // Restore the original wiki reference in the context
            xcontext.setWikiReference(currentWiki);
        }

    }

    /**
     * @param clientID the client id
     * @return the client
     * @throws XWikiException when failing to load the client
     * @since 2.21.0
     */
    public BaseObjectOIDCClient getClient(ClientID clientID) throws XWikiException
    {
        // Load the user document containing the clients configurations
        XWikiDocument userDocument = getClientsDocument();

        // Make sure to avoid modifying the cached document
        userDocument = userDocument.clone();

        // Return the client configuration for the given client ID
        return getClient(clientID != null ? clientID.getValue() : null, userDocument);
    }

    private BaseObjectOIDCClient getClient(String clientID, XWikiDocument clientsDocument)
    {
        if (clientsDocument.isNew()) {
            return null;
        }

        this.logger.debug("Get stored OIDC client for id [{}]", clientID);

        // Try to find an enabled dynamic configuration first
        BaseObject dynamicClient = getDynamicClient(clientsDocument);
        if (dynamicClient != null) {
            this.logger.debug("  -> A dynamic configuration was found: [{}]", dynamicClient.getReference());

            // If a dynamic configuration is found and enabled, use it without trying to find a specific one for the
            // client ID (the dynamic configuration has priority over the static ones)
            return new BaseObjectOIDCClient(dynamicClient, this.xcontextProvider.get());
        }

        if (clientID != null) {
            // Try to find a configuration specific to the client ID
            List<BaseObject> clients = clientsDocument.getXObjects(BaseObjectOIDCClient.REFERENCE);
            if (clients != null) {
                return getClient(clientID, clients);
            }
        }

        return null;
    }

    private BaseObjectOIDCClient getClient(String clientID, List<BaseObject> clients)
    {
        for (BaseObject client : clients) {
            if (client != null) {
                String clientIdValue = BaseObjectOIDCClient.getClientID(client);
                if (clientIdValue != null && clientIdValue.equals(clientID)) {
                    if (BaseObjectOIDCClient.isEnabled(client)) {
                        this.logger.debug("  -> A specific configuration was found for the client ID: [{}]",
                            client.getReference());

                        return new BaseObjectOIDCClient(client, this.xcontextProvider.get());
                    } else {
                        this.logger.debug(
                            "  -> A specific configuration was found for the client ID, but it is disabled: [{}]",
                            client.getReference());
                    }
                }
            }
        }

        return null;
    }

    private BaseObject getDynamicClient() throws XWikiException
    {
        // Load the user document containing the clients configurations
        XWikiDocument userDocument = getClientsDocument();

        return getDynamicClient(userDocument);
    }

    private BaseObject getDynamicClient(XWikiDocument clientsDocument)
    {
        BaseObject dynamicClient =
            clientsDocument.getXObject(BaseObjectOIDCClient.REFERENCE, BaseObjectOIDCClient.FIELD_ID, "", false);
        if (dynamicClient != null && BaseObjectOIDCClient.isEnabled(dynamicClient)) {
            return dynamicClient;
        }

        return null;
    }

    /**
     * @return true if dynamic client registration is enabled, false otherwise
     * @throws XWikiException when failing to load the clients configuration
     */
    public boolean isDynamicClientRegistration() throws XWikiException
    {
        return getDynamicClient() != null;
    }
}
