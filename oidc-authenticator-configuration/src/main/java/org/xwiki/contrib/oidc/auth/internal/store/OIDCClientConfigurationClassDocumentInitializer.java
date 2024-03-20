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

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.TextAreaClass;

/**
 * Document initializer for the OIDC client configuration class.
 *
 * @version $Id$
 * @since 1.30
 */
@Component
@Named(OIDCClientConfiguration.CLASS_FULLNAME)
@Singleton
public class OIDCClientConfigurationClassDocumentInitializer extends AbstractMandatoryClassInitializer
{
    private static final String INPUT = "input";

    private static final String SEPARATORS = "|,";

    /**
     * Builds a new {@link OIDCClientConfigurationClassDocumentInitializer}.
     */
    public OIDCClientConfigurationClassDocumentInitializer()
    {
        super(OIDCClientConfiguration.CLASS_REFERENCE, "OpenID Connect Client Configuration Class");
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(OIDCClientConfiguration.FIELD_CONFIGURATION_NAME, "Configuration name", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_CLAIM_GROUP, "Group claim", 255);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_GROUP_MAPPING, "Group mapping", 50, 10,
            TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_ALLOWED_GROUPS, "Allowed groups", 50, 10,
            TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_FORBIDDEN_GROUPS, "Forbidden groups", 50, 10,
            TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addTextField(OIDCClientConfiguration.FIELD_FORMATTER_USER_SUBJECT, "Subject formatter", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_FORMATTER_USER_NAME, "XWiki username formatter", 255);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_USER_MAPPING, "User mapping", 50, 10,
            TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addTextField(OIDCClientConfiguration.FIELD_XWIKI_PROVIDER, "XWiki provider", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_AUTHORIZATION, "Authorization OIDC endpoint", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_TOKEN, "Token OIDC endpoint", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_USERINFO, "User info OIDC endpoint", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_LOGOUT, "Logout OIDC endpoint", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_CLIENT_ID, "Client ID", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_CLIENT_SECRET, "Secret", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_TOKEN_METHOD,
            "Token endpoint authentication method", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_USERINFO_METHOD,
            "User information endpoint method", 255);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_ENDPOINT_USERINFO_HEADERS, "User info endpoint headers",
            50, 10, TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addTextField(OIDCClientConfiguration.FIELD_ENDPOINT_LOGOUT_METHOD, "Logout endpoint method", 255);
        xclass.addTextField(OIDCClientConfiguration.FIELD_LOGOUT_MECHANISM, "Logout mechanism", 255);
        xclass.addBooleanField(OIDCClientConfiguration.FIELD_SKIPPED, "Is authentication skipped ?", "select");
        xclass.addTextField(OIDCClientConfiguration.FIELD_SCOPE, "Scope", 255);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_CLAIMS_ID_TOKEN, "ID Token Claims", 50, 10,
            TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addTextAreaField(OIDCClientConfiguration.FIELD_CLAIMS_USER_INFO, "User info Claims", 50, 10,
            TextAreaClass.EditorType.PURE_TEXT, TextAreaClass.ContentType.PURE_TEXT);
        xclass.addNumberField(OIDCClientConfiguration.FIELD_USER_INFO_REFRESH_RATE, "User info refresh rate", 5,
            "integer");
        xclass.addTextField(OIDCClientConfiguration.FIELD_USER_PROFILE_ACTIVATION_STRATEGY,
            "User profile activation strategy", 255);
    }
}
