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
package org.xwiki.contrib.oidc.consent.internal.store;

import java.util.List;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Update the access tokens stored in the consents.
 *
 * @version $Id$
 */
@Component(roles = OIDCConsentAccessTokenUpdater.class)
@Singleton
public class OIDCConsentAccessTokenUpdater
{
    /**
     * The prefixes of a value produced by {@link com.xpn.xwiki.objects.classes.PasswordClass} with the Hash storage
     * type: {@code hash:<algorithm>:<salt>:<hash>} (before XWiki 17.10.14) or {@code {<algorithm>}<hash>}.
     */
    private static final Pattern HASHED_VALUE = Pattern.compile("^(hash:|\\{[\\w-]+\\})");

    /**
     * The number of checked documents between two progress logs.
     */
    private static final int PROGRESS_STEP = 100;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private QueryManager queryManager;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Inject
    private EntityReferenceSerializer<String> serializer;

    @Inject
    private Logger logger;

    /**
     * Reset the access tokens which are not stored as a hash in the consents of the current wiki.
     * <p>
     * A failure to update a document is logged and does not stop the process.
     *
     * @throws OIDCException when failing to search the documents containing consents
     */
    public void resetNotHashedAccessTokens() throws OIDCException
    {
        List<String> documents;
        try {
            documents = this.queryManager
                .<String>createQuery("select distinct obj.name from BaseObject as obj where obj.className = :className",
                    Query.HQL)
                .bindValue("className", BaseObjectOIDCConsent.REFERENCE_STRING).execute();
        } catch (QueryException e) {
            throw new OIDCException("Failed to search the documents containing consents", e);
        }

        String wiki = this.xcontextProvider.get().getWikiId();

        this.logger.info("Checking the OIDC access tokens stored in [{}] documents of wiki [{}]", documents.size(),
            wiki);

        int resetTokens = 0;
        int modifiedDocuments = 0;
        int failedDocuments = 0;
        int checkedDocuments = 0;
        for (String document : documents) {
            DocumentReference documentReference = this.resolver.resolve(document);

            try {
                int documentResetTokens = resetNotHashedAccessTokens(documentReference);
                if (documentResetTokens > 0) {
                    resetTokens += documentResetTokens;
                    ++modifiedDocuments;
                }
            } catch (XWikiException e) {
                // Don't stop the whole process because of a single document
                this.logger.error("Failed to reset the OIDC access tokens in document [{}]", documentReference, e);
                ++failedDocuments;
            }

            ++checkedDocuments;
            if (checkedDocuments % PROGRESS_STEP == 0 || checkedDocuments == documents.size()) {
                this.logger.info("[{}/{}] documents checked", checkedDocuments, documents.size());
            }
        }

        this.logger.info("[{}] OIDC access tokens have been reset in [{}] documents of wiki [{}] ([{}] failures)",
            resetTokens, modifiedDocuments, wiki, failedDocuments);
    }

    /**
     * @return the number of reset access tokens
     */
    private int resetNotHashedAccessTokens(DocumentReference documentReference) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        // Make sure to avoid modifying the cached document
        XWikiDocument document = xcontext.getWiki().getDocument(documentReference, xcontext).clone();

        int resetTokens = 0;
        for (BaseObject consentObject : document.getXObjects(BaseObjectOIDCConsent.REFERENCE)) {
            if (consentObject != null) {
                String stored = consentObject.getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN);
                if (StringUtils.isNotEmpty(stored) && !HASHED_VALUE.matcher(stored).find()) {
                    new BaseObjectOIDCConsent(this.serializer.serialize(consentObject.getReference()), consentObject,
                        xcontext).setAccessToken(null);
                    ++resetTokens;
                }
            }
        }

        if (resetTokens > 0) {
            xcontext.getWiki().saveDocument(document, "Reset OIDC access tokens", true, xcontext);

            this.logger.debug("[{}] OIDC access tokens have been reset in document [{}]", resetTokens,
                documentReference);
        }

        return resetTokens;
    }
}
