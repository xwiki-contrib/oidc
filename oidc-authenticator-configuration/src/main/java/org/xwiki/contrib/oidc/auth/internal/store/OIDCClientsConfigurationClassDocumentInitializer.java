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

import java.util.Arrays;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;

/**
 * Document initializer for the OIDC clients configuration class. This class holds app-wide configuration data such as
 * the default OIDC client used for authentication.
 *
 * @version $Id$
 * @since 2.28.0
 */
@Component
@Named(OIDCClientsConfigurationClassDocumentInitializer.CLASS_FULLNAME)
@Singleton
public class OIDCClientsConfigurationClassDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * The serialized reference of the class document.
     */
    public static final String CLASS_FULLNAME = "XWiki.OIDC.ClientsConfigurationClass";

    /**
     * The local reference of the configuration class.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "ClientsConfigurationClass");

    /**
     * The name of the property in which the name of the OIDC configuration should be stored.
     *
     */
    public static final String FIELD_CLIENT_CONFIGURATION_COOKIE = "clientConfigurationCookie";

    /**
     * The name of the property which stores the name of the default OIDC client configuration.
     *
     */
    public static final String FIELD_DEFAULT_CLIENT_CONFIGURATION = "defaultClientConfiguration";

    /**
     * Default constructor.
     */
    public OIDCClientsConfigurationClassDocumentInitializer()
    {
        super(CLASS_REFERENCE, "OpenID Connect Clients Configuration Class");
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(FIELD_CLIENT_CONFIGURATION_COOKIE, "Client Configuration Cookie", 20);
        xclass.addTextField(FIELD_DEFAULT_CLIENT_CONFIGURATION, "Default Client Configuration", 20);
    }
}
