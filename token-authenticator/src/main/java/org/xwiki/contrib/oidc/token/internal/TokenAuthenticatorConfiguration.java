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
package org.xwiki.contrib.oidc.token.internal;

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.internal.OIDCConfiguration;

/**
 * Various OpenID Connect authenticator configurations.
 * 
 * @version $Id$
 * @since 2.21.0
 */
@Component(roles = TokenAuthenticatorConfiguration.class)
@Singleton
public class TokenAuthenticatorConfiguration extends OIDCConfiguration
{
    /**
     * The prefix used for Token Authenticator configuration properties.
     */
    public static final String PREFIX_PROP = OIDCConfiguration.PREFIX_PROP + "token.";

    /**
     * The name of the property containing the authenticator to fallback to.
     */
    public static final String PROP_AUTHENTICATOR = PREFIX_PROP + "authenticator";

    /**
     * The former name of the property containing the authenticator to fallback to.
     */
    private static final String PROP_AUTHENTICATOR_LEGACY = OIDCConfiguration.PREFIX_PROP + "provider.authenticator";

    /**
     * @return the authenticator to fallback to
     */
    public String getAuthenticator()
    {
        String authenticator = getProperty(PROP_AUTHENTICATOR, (String) null);

        if (authenticator == null) {
            // Try the legacy property for backward compatibility.
            authenticator = getProperty(PROP_AUTHENTICATOR_LEGACY, (String) null);
        }

        return authenticator;
    }
}
