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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
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
import org.xwiki.context.Execution;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration.SubFormat;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.observation.ObservationManager;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceSerializer;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Allow manipulating consents.
 * 
 * @version $Id$
 */
@Component(roles = OIDCStore.class)
@Singleton
public class OIDCStore
{
    private static final String ALLOWED_MODIFICATION = "OIDCStore.allowedmodification";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Inject
    private EntityReferenceResolver<String> entityResolver;

    @Inject
    private EntityReferenceSerializer<String> referenceSerializer;

    @Inject
    private OIDCProviderConfiguration configuration;

    @Inject
    private EntityReferenceSerializer<String> defaultReferenceSerializer;

    @Inject
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    @Inject
    private ObservationManager observation;

    @Inject
    private Execution execution;

    @Inject
    private Logger logger;

    Map<String, AuthorizationSession> authorizationSessionMap = new ConcurrentHashMap<>();

    public BaseObjectOIDCConsent getConsent(XWikiBearerAccessToken xwikiAccessToken) throws XWikiException
    {
        EntityReference reference =
            this.entityResolver.resolve(xwikiAccessToken.getDocumentObjectReference(), EntityType.OBJECT);

        XWikiContext xcontext = this.xcontextProvider.get();

        // Get the document containing the consent
        XWikiDocument consentDocument = xcontext.getWiki().getDocument(reference, xcontext);

        // Make sure the document exist
        if (!consentDocument.isNew()) {
            // Get the consent object
            BaseObject consentObject = consentDocument.getXObject(reference);
            if (consentObject != null) {
                BaseObjectOIDCConsent consent = new BaseObjectOIDCConsent(
                    this.defaultReferenceSerializer.serialize(consentObject.getReference()), consentObject, xcontext);

                // Validate token:
                // * must be enabled
                // * must not be expired
                // * must match the stored token value
                if (consent.isEnabled()
                    && (consent.getAccessTokenExpiration() == null
                        || consent.getAccessTokenExpiration().after(new Date()))
                    && consent.isTokenValid(xwikiAccessToken)) {
                    return consent;
                }
            }
        }

        return null;
    }

    public BaseObjectOIDCConsent getConsent(ClientID clientID, URI redirectURI, AuthorizationCode code)
        throws XWikiException
    {
        DocumentReference userReference = getUserReference(code);

        if (userReference == null) {
            return null;
        }

        return getConsent(clientID, redirectURI, userReference);
    }

    public BaseObjectOIDCConsent getConsent(ClientID clientID, URI redirectURI, DocumentReference userReference)
        throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);

        return getConsent(clientID, redirectURI, userDocument);
    }

    public BaseObjectOIDCConsent getConsent(ClientID clientID, URI redirectURI, XWikiDocument userDocument)
    {
        this.logger.debug("Get consent USER: reference={}", userDocument.getDocumentReference());

        if (userDocument.isNew()) {
            return null;
        }

        String clientIDString = clientID != null ? clientID.getValue() : "";
        String redirectURIString = redirectURI.toString();

        this.logger.debug("Get consent OIDC: clientIDString={} redirectURIString={}", clientIDString,
            redirectURIString);

        List<BaseObject> consents = userDocument.getXObjects(BaseObjectOIDCConsent.REFERENCE);
        if (consents != null) {
            for (BaseObject consentObject : consents) {
                if (consentObject != null) {
                    this.logger.debug("Get consent STORED: clientIDString={} redirectURIString={}",
                        consentObject.getStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID),
                        consentObject.getStringValue(BaseObjectOIDCConsent.FIELD_REDIRECTURI));

                    if (clientIDString.equals(consentObject.getStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID))
                        && redirectURIString
                            .equals(consentObject.getStringValue(BaseObjectOIDCConsent.FIELD_REDIRECTURI))) {
                        return new BaseObjectOIDCConsent(
                            this.defaultReferenceSerializer.serialize(consentObject.getReference()), consentObject,
                            this.xcontextProvider.get());
                    }
                }
            }
        }

        return null;
    }

    public XWikiDocument getCurrentUserDocument() throws OIDCException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        try {
            return xcontext.getWiki().getDocument(xcontext.getUserReference(), xcontext);
        } catch (XWikiException e) {
            throw new OIDCException("Failed to load the document of the current user", e);
        }
    }

    private XWikiDocument getUserDocument(UserReference userReference) throws OIDCException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        try {
            return xcontext.getWiki().getDocument(this.userReferenceSerializer.serialize(userReference), xcontext);
        } catch (XWikiException e) {
            throw new OIDCException("Failed to load the document of the user [" + userReference + "]", e);
        }
    }

    public XWikiBearerAccessToken createAccessToken(BaseObjectOIDCConsent consent)
    {
        // TODO: set a configurable default lifespan ?
        return createAccessToken(consent, null);
    }

    public XWikiBearerAccessToken createAccessToken(BaseObjectOIDCConsent consent, Date expirationDate)
    {
        // TODO: set a configurable default scope ? readonly by default ?
        XWikiBearerAccessToken accessToken = XWikiBearerAccessToken
            .create(this.defaultReferenceSerializer.serialize(consent.getReference()), expirationDate);
        consent.setAccessToken(accessToken);

        return accessToken;
    }

    public BaseObjectOIDCConsent createCurrentUserConsent() throws OIDCException
    {
        XWikiDocument userDocument = getCurrentUserDocument();

        // Clone the document to avoid concurrency problems
        userDocument = userDocument.clone();

        // TODO: set a configurable default lifespan ?
        return createUserConsent(userDocument, null);
    }

    public BaseObjectOIDCConsent createAndSaveConsent(UserReference userReference, ClientID clientID,
        Date expirationDate) throws OIDCException
    {
        XWikiDocument userDocument = getUserDocument(userReference);

        // Clone the document to avoid concurrency problems
        userDocument = userDocument.clone();

        BaseObjectOIDCConsent consent = createUserConsent(userDocument, expirationDate);

        // Set the client ID
        consent.setClientID(clientID);

        // Save the new consent
        saveConsent(consent, "Create a new consent");

        return consent;
    }

    public BaseObjectOIDCConsent createUserConsent(XWikiDocument userDocument, Date expirationDate) throws OIDCException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject consentObject;
        try {
            consentObject = userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        } catch (XWikiException e) {
            throw new OIDCException("Failed to create a new consent", e);
        }

        BaseObjectOIDCConsent consent = new BaseObjectOIDCConsent(
            this.defaultReferenceSerializer.serialize(consentObject.getReference()), consentObject, xcontext);

        // Create a token
        createAccessToken(consent, expirationDate);

        return consent;
    }

    public XWikiBearerAccessToken createAndSaveAccessToken(BaseObjectOIDCConsent consent) throws OIDCException
    {
        XWikiBearerAccessToken accessToken = createAccessToken(consent);
        saveConsent(consent, "Update OIDC access token");

        return accessToken;
    }

    public BaseObjectOIDCConsent saveConsent(BaseObjectOIDCConsent consent, String comment) throws OIDCException
    {
        XWikiDocument userDocument = consent.getOwnerDocument();

        XWikiContext xcontext = this.xcontextProvider.get();

        try {
            // Allow modifying consents
            setConsentModificationAllowed();

            xcontext.getWiki().saveDocument(userDocument, comment, xcontext);
        } catch (XWikiException e) {
            throw new OIDCException("Failed to save consent", e);
        } finally {
            // Don't all modifying consents anymore
            unsetConsentModificationAllowed();
        }

        return consent;
    }

    public BaseObject getUserObject(BaseObjectOIDCConsent consent) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        XWikiDocument userDocument = consent.getOwnerDocument();

        return userDocument.getXObject(xcontext.getWiki().getUserClass(xcontext).getDocumentReference());
    }

    public URI getUserAvatarURI(XWikiDocument userDocument) throws URISyntaxException
    {
        String avatar = userDocument.getStringValue("avatar");

        return StringUtils.isEmpty(avatar) ? null
            : new URI(userDocument.getExternalAttachmentURL(avatar, "download", this.xcontextProvider.get()));
    }

    public URI getUserProfileURI(XWikiDocument userDocument) throws URISyntaxException
    {
        return new URI(userDocument.getExternalURL("view", this.xcontextProvider.get()));
    }

    public DocumentReference getUserReference(AuthorizationCode code)
    {
        AuthorizationSession session = this.authorizationSessionMap.get(code.getValue());

        return session != null ? session.getUserReference() : null;
    }

    /**
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

    public void deleteAuthorizationCode(AuthorizationCode code)
    {
        if (code != null) {
            this.logger.debug("Delete authorization code [{}]", code);

            this.observation.notify(new AuthorizationCodeDeletedEvent(code), null);
        }
    }

    /**
     * @param userReference the reference of the user for which to return the consents
     * @return the consents of the user
     * @throws OIDCException when failing to load the user's consents
     * @since 2.13.0
     */
    public List<BaseObjectOIDCConsent> getConsents(UserReference userReference) throws OIDCException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        XWikiDocument userDocument = getUserDocument(userReference);

        List<BaseObject> consentObjects = userDocument.getXObjects(BaseObjectOIDCConsent.REFERENCE);

        if (consentObjects != null) {
            List<BaseObjectOIDCConsent> consents = new ArrayList<>(consentObjects.size());

            for (BaseObject consentObject : consentObjects) {
                if (consentObject != null) {
                    consents.add(new BaseObjectOIDCConsent(
                        this.defaultReferenceSerializer.serialize(consentObject.getReference()), consentObject,
                        xcontext));
                }
            }

            return consents;
        }

        return Collections.emptyList();
    }

    private void setConsentModificationAllowed()
    {
        this.execution.getContext().setProperty(ALLOWED_MODIFICATION, Boolean.TRUE);
    }

    private void unsetConsentModificationAllowed()
    {
        this.execution.getContext().removeProperty(ALLOWED_MODIFICATION);
    }

    /**
     * @param id the identifier of the consent
     * @throws OIDCException when failing to delete the consent
     */
    public void deleteConsent(String id) throws OIDCException
    {
        // The id is actually the reference of the xobject holding the consent
        EntityReference reference = this.entityResolver.resolve(id, EntityType.OBJECT);

        XWikiContext xcontext = this.xcontextProvider.get();

        // Get the document containing the consent
        XWikiDocument consentDocument;
        try {
            consentDocument = xcontext.getWiki().getDocument(reference, xcontext);
        } catch (XWikiException e) {
            throw new OIDCException("Failed to load the consent document for id [" + id + "]", e);
        }

        // Make sure the document exist
        if (!consentDocument.isNew()) {
            // Get the consent object
            BaseObject consentObject = consentDocument.getXObject(reference);
            if (consentObject != null) {
                // Remove the xobject
                if (consentDocument.removeXObject(consentObject)) {
                    // Save the modified document
                    try {
                        xcontext.getWiki().saveDocument(consentDocument, xcontext);
                    } catch (XWikiException e) {
                        throw new OIDCException("Failed to delete the consent for id [" + id + "]", e);
                    }
                }
            }
        }
    }
}
