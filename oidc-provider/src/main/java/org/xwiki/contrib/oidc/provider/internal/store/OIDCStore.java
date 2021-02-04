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
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceResolver;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.PasswordClass;

@Component(roles = OIDCStore.class)
@Singleton
public class OIDCStore
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Inject
    private EntityReferenceResolver<String> entityResolver;

    @Inject
    private Logger logger;

    private Map<AuthorizationCode, AuthorizationSession> sessionMap = new ConcurrentHashMap<>();

    private class AuthorizationSession
    {
        final DocumentReference userReference;

        final Nonce nonce;

        AuthorizationSession(DocumentReference userReference, Nonce nonce)
        {
            this.userReference = userReference;
            this.nonce = nonce;
        }
    }

    public OIDCConsent getConsent(DocumentReference userReference, ClientID clientID, URI redirectURI)
        throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);
        for (OIDCConsent consent : (List<OIDCConsent>) (List) userDocument.getXObjects(OIDCConsent.REFERENCE)) {
            if (consent != null) {
                if (clientID.equals(consent.getClientID())
                    && (redirectURI == null || redirectURI.equals(consent.getRedirectURI()))) {
                    return consent;
                }
            }
        }

        return null;
    }

    public OIDCConsent getConsent(XWikiBearerAccessToken xwikiAccessToken) throws XWikiException
    {
        EntityReference reference =
            this.entityResolver.resolve(xwikiAccessToken.getObjectReference(), EntityType.OBJECT);

        XWikiContext xcontext = this.xcontextProvider.get();

        // Get the document containing the consent
        XWikiDocument consentDocument = xcontext.getWiki().getDocument(reference, xcontext);

        // Get the consent
        OIDCConsent consent = (OIDCConsent) consentDocument.getXObject(reference);

        // Compare token values
        final String stored = consent.getStringValue(OIDCConsent.FIELD_ACCESSTOKEN);
        if (new PasswordClass().getEquivalentPassword(stored, xwikiAccessToken.getRandom()).equals(stored)) {
            return consent;
        }

        return null;
    }

    public OIDCConsent getConsent(ClientID clientID, URI redirectURI, AuthorizationCode code) throws XWikiException
    {
        DocumentReference userReference = getUserReference(code);

        if (userReference == null) {
            return null;
        }

        return getConsent(clientID, redirectURI, userReference);
    }

    public OIDCConsent getConsent(ClientID clientID, URI redirectURI, DocumentReference userReference)
        throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);

        return getConsent(clientID, redirectURI, userDocument);
    }

    public OIDCConsent getConsent(ClientID clientID, URI redirectURI, XWikiDocument userDocument)
    {
        this.logger.debug("Get consent USER: reference={}", userDocument.getDocumentReference());

        if (userDocument.isNew()) {
            return null;
        }

        String clientIDString = clientID != null ? clientID.getValue() : "";
        String redirectURIString = redirectURI.toString();

        this.logger.debug("Get consent OIDC: clientIDString={} redirectURIString={}", clientIDString,
            redirectURIString);

        List<BaseObject> consents = userDocument.getXObjects(OIDCConsent.REFERENCE);
        if (consents != null) {
            for (BaseObject consent : consents) {
                if (consent != null) {
                    this.logger.debug("Get consent STORED: clientIDString={} redirectURIString={}",
                        consent.getStringValue(OIDCConsent.FIELD_CLIENTID),
                        consent.getStringValue(OIDCConsent.FIELD_REDIRECTURI));

                    if (clientIDString.equals(consent.getStringValue(OIDCConsent.FIELD_CLIENTID))
                        && redirectURIString.equals(consent.getStringValue(OIDCConsent.FIELD_REDIRECTURI))) {
                        return (OIDCConsent) consent;
                    }
                }
            }
        }

        return null;
    }

    public XWikiDocument getUserDocument() throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        return xcontext.getWiki().getDocument(xcontext.getUserReference(), xcontext);
    }

    public OIDCConsent saveConsent(OIDCConsent consent, String comment) throws XWikiException
    {
        XWikiDocument userDocument = consent.getOwnerDocument();

        XWikiContext xcontext = this.xcontextProvider.get();

        xcontext.getWiki().saveDocument(userDocument, comment, xcontext);

        return consent;
    }

    public BaseObject getUserObject(OIDCConsent consent) throws XWikiException
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
        AuthorizationSession session = this.sessionMap.get(code);

        return session != null ? session.userReference : null;
    }

    /**
     * @since 1.24
     */
    public Nonce getNonce(AuthorizationCode code)
    {
        AuthorizationSession session = this.sessionMap.get(code);

        return session != null ? session.nonce : null;
    }

    /**
     * @since 1.24
     */
    public void setAuthorizationCode(AuthorizationCode code, DocumentReference userReference, Nonce nonce)
    {
        this.sessionMap.put(code, new AuthorizationSession(userReference, nonce));
    }

    public void removeAuthorizationCode(AuthorizationCode code)
    {
        this.sessionMap.remove(code);
    }
}
