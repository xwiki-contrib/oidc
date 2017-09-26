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
import java.util.HashMap;
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
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

@Component(roles = OIDCStore.class)
@Singleton
public class OIDCStore
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private QueryManager queryManager;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Inject
    private Logger logger;

    private Map<AuthorizationCode, DocumentReference> authorizationMap = new ConcurrentHashMap<>();

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

    public OIDCConsent getConsent(Map<String, String> entries) throws QueryException, XWikiException
    {
        StringBuilder builder = new StringBuilder();

        for (String key : entries.keySet()) {
            if (builder.length() == 0) {
                builder.append("select doc.fullName, consent.number from Document doc, doc.object("
                    + OIDCConsent.REFERENCE_STRING + ") as consent where ");
            } else {
                builder.append(" AND ");
            }

            builder.append("consent." + key + " = :" + key);
        }

        Query query = this.queryManager.createQuery(builder.toString(), Query.XWQL);

        for (Map.Entry<String, String> entry : entries.entrySet()) {
            query.bindValue(entry.getKey(), entry.getValue());
        }

        List<Object[]> users = query.execute();

        if (users.isEmpty()) {
            return null;
        }

        // TODO: return an error when there is several ?

        Object[] user = users.get(0);

        XWikiContext xcontext = this.xcontextProvider.get();

        DocumentReference userReference = this.resolver.resolve((String) user[0]);
        XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);

        return (OIDCConsent) userDocument.getXObject(OIDCConsent.REFERENCE, ((Number) user[1]).intValue());
    }

    public OIDCConsent getConsent(AccessToken accessToken) throws QueryException, XWikiException
    {
        Map<String, String> entries = new HashMap<>();

        entries.put(OIDCConsent.FIELD_ACCESSTOKEN, accessToken.getValue());

        return getConsent(entries);
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
        return this.authorizationMap.get(code);
    }

    public void setAuthorizationCode(AuthorizationCode code, DocumentReference userReference)
    {
        this.authorizationMap.put(code, userReference);
    }

    public void removeAuthorizationCode(AuthorizationCode code)
    {
        this.authorizationMap.remove(code);
    }
}
