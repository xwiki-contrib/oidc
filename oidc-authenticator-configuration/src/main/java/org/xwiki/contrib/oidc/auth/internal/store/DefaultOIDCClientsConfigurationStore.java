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

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCClientsConfigurationStore;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Default implementation of {@link OIDCClientsConfigurationStore}, reading the configuration stored in the
 * {@link OIDCClientsConfigurationDocumentInitializer#REFERENCE} document of the current wiki.
 *
 * @version $Id$
 * @since 2.28.0
 */
@Component
@Singleton
public class DefaultOIDCClientsConfigurationStore implements OIDCClientsConfigurationStore
{
    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private AuthorizationManager authorizationManager;

    @Inject
    private Logger logger;

    @Override
    public String getClientConfigurationCookie()
    {
        return getValue(OIDCClientsConfigurationClassDocumentInitializer.FIELD_CLIENT_CONFIGURATION_COOKIE);
    }

    @Override
    public String getDefaultClientConfiguration()
    {
        return getValue(OIDCClientsConfigurationClassDocumentInitializer.FIELD_DEFAULT_CLIENT_CONFIGURATION);
    }

    private String getValue(String field)
    {
        BaseObject xobject = getConfigurationObject();
        if (xobject != null) {
            String value = xobject.getStringValue(field);
            if (StringUtils.isNotBlank(value)) {
                return value;
            }
        }

        return null;
    }

    private BaseObject getConfigurationObject()
    {
        XWikiContext xcontext = this.contextProvider.get();

        try {
            XWikiDocument document = xcontext.getWiki()
                .getDocument(OIDCClientsConfigurationDocumentInitializer.REFERENCE, xcontext);

            // Make sure the configuration was set by someone allowed to do it
            if (!this.authorizationManager.hasAccess(Right.ADMIN, document.getAuthorReference(),
                document.getDocumentReference().getWikiReference())) {
                this.logger.debug(
                    "Ignoring the OIDC clients configuration from document [{}]"
                        + " because the author [{}] does not have wiki ADMIN right",
                    document.getDocumentReference(), document.getAuthorReference());

                return null;
            }

            return document.getXObject(OIDCClientsConfigurationClassDocumentInitializer.CLASS_REFERENCE);
        } catch (XWikiException e) {
            this.logger.error("Failed to load the OIDC clients configuration in wiki [{}]", xcontext.getWikiId(), e);
        }

        return null;
    }
}
