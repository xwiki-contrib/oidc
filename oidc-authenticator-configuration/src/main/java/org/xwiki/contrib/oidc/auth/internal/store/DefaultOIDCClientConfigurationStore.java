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
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Default implementation for the {@link OIDCClientConfigurationStore}.
 *
 * @version $Id$
 * @since 1.30
 */
@Component
@Singleton
public class DefaultOIDCClientConfigurationStore implements OIDCClientConfigurationStore
{
    @Inject
    private QueryManager queryManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Override
    public XWikiDocument getOIDCClientConfigurationDocument(String name) throws XWikiException, QueryException
    {
        Query query = queryManager.createQuery(
            "select obj.name from BaseObject obj, StringProperty configName "
            + "where obj.className = :className and obj.id = configName.id.id "
            + "and configName.id.name = :configFieldName and configName.value = :config", Query.HQL)
            .bindValue("className", OIDCClientConfiguration.CLASS_FULLNAME)
            .bindValue("configFieldName", OIDCClientConfiguration.FIELD_CONFIGURATION_NAME)
            .bindValue("config", name);
        List<String> results = query.execute();

        if (results.size() > 0) {
            XWikiContext context = contextProvider.get();
            XWiki xwiki = context.getWiki();

            return xwiki.getDocument(documentReferenceResolver.resolve(results.get(0)), context);
        } else {
            return null;
        }
    }

    @Override
    public OIDCClientConfiguration getOIDCClientConfiguration(String name)
        throws XWikiException, QueryException
    {
        XWikiDocument configurationDocument = getOIDCClientConfigurationDocument(name);

        if (configurationDocument != null) {
            return new OIDCClientConfiguration(
                configurationDocument.getXObject(OIDCClientConfiguration.CLASS_REFERENCE));
        }

        return null;
    }
}
