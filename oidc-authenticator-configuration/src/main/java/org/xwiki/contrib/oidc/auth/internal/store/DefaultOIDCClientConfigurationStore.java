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
import java.util.Objects;
import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCClientConfigurationCache.CacheEntry;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

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
    private OIDCClientConfigurationCache cache;

    @Inject
    private QueryManager queryManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private AuthorizationManager authorizationManager;

    @Override
    public XWikiDocument getOIDCClientConfigurationDocument(String name) throws XWikiException, QueryException
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        // Search for a configuration in the current wiki and in the main wiki
        List<String> results = getOIDCClientConfigurationDocumentQuery(name).execute();
        if (!context.isMainWiki()) {
            results.addAll(getOIDCClientConfigurationDocumentQuery(name).setWiki(XWiki.DEFAULT_MAIN_WIKI).execute());
        }

        if (results.size() > 0) {
            for (String result : results) {
                XWikiDocument document = xwiki.getDocument(documentReferenceResolver.resolve(result), context);

                if (authorizationManager.hasAccess(Right.ADMIN, document.getAuthorReference(),
                    document.getDocumentReference().getWikiReference())) {
                    return document;
                }
            }
        }

        return null;
    }

    private Query getOIDCClientConfigurationDocumentQuery(String name) throws QueryException
    {
        return queryManager.createQuery(
                "select obj.name from BaseObject obj, StringProperty configName "
                    + "where obj.className = :className and obj.id = configName.id.id "
                    + "and configName.id.name = :configFieldName and configName.value = :config", Query.HQL)
            .bindValue("className", OIDCClientConfiguration.CLASS_FULLNAME)
            .bindValue("configFieldName", OIDCClientConfiguration.FIELD_CONFIGURATION_NAME)
            .bindValue("config", name);
    }

    @Override
    public OIDCClientConfiguration getOIDCClientConfiguration(String name) throws XWikiException, QueryException
    {
        // Check if the configuration (or the fact that there is no configuration) is already in the cache
        CacheEntry entry = this.cache.get(name);
        if (entry != null) {
            return entry.getConfiguration();
        }

        // Find the configuration
        OIDCClientConfiguration configuration = null;
        XWikiDocument configurationDocument = getOIDCClientConfigurationDocument(name);
        if (configurationDocument != null) {
            Optional<BaseObject> configObj = configurationDocument.getXObjects(OIDCClientConfiguration.CLASS_REFERENCE)
                .stream()
                .filter(Objects::nonNull)
                .filter(
                    x -> StringUtils.equals(name, x.getStringValue(OIDCClientConfiguration.FIELD_CONFIGURATION_NAME)))
                .findFirst();
            if (configObj.isPresent()) {
                configuration = new OIDCClientConfiguration(configObj.get());
            }
        }

        // Cache the configuration
        this.cache.set(name, configuration);

        return configuration;
    }
}
