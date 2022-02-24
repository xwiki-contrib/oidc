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
package org.xwiki.contrib.oidc.auth.internal.store;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCUser;
import org.xwiki.contrib.oidc.auth.store.OIDCUserStore;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Helper to manager OpenID Connect profiles XClass and XObject.
 * 
 * @version $Id: c68c46c340eb3dd4988644e71d45541e9c1f25eb $
 */
@Component
@Singleton
public class DefaultOIDCUserStore implements OIDCUserStore
{
    @Inject
    private QueryManager queries;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Override
    public boolean updateOIDCUser(XWikiDocument userDocument, String issuer, String subject)
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        OIDCUser user = new OIDCUser(userDocument.getXObject(OIDCUser.CLASS_REFERENCE, true, xcontext));

        boolean needUpdate = false;

        if (!StringUtils.equals(user.getIssuer(), issuer)) {
            user.setIssuer(issuer);
            needUpdate = true;
        }

        if (!StringUtils.equals(user.getSubject(), subject)) {
            user.setSubject(subject);
            needUpdate = true;
        }

        return needUpdate;
    }

    @Override
    public XWikiDocument searchDocument(String issuer, String subject) throws XWikiException, QueryException
    {
        Query query = this.queries.createQuery("from doc.object(" + OIDCUser.CLASS_FULLNAME
            + ") as oidc where oidc.issuer = :issuer and oidc.subject = :subject", Query.XWQL);

        query.bindValue("issuer", issuer);
        query.bindValue("subject", subject);

        List<String> documents = query.execute();

        if (documents.isEmpty()) {
            return null;
        }

        // TODO: throw exception when there is several ?

        XWikiContext xcontext = this.xcontextProvider.get();

        DocumentReference userReference = this.resolver.resolve(documents.get(0));
        XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);

        if (userDocument.isNew()) {
            return null;
        }

        return userDocument;
    }
}
