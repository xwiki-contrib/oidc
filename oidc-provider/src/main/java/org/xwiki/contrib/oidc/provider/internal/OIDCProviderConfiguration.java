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
package org.xwiki.contrib.oidc.provider.internal;

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.internal.OIDCConfiguration;

/**
 * Various OpenID Connect authenticator configurations.
 * 
 * @version $Id$
 * @since 1.15
 */
@Component(roles = OIDCProviderConfiguration.class)
@Singleton
public class OIDCProviderConfiguration extends OIDCConfiguration
{
    /**
     * The prefix used for OpenID Connect Provider configuration properties.
     */
    public static final String PREFIX_PROP = OIDCConfiguration.PREFIX_PROP + "provider.";

    /**
     * The name of the property containing the authenticator to fallback to.
     */
    public static final String PROP_AUTHENTICATOR = PREFIX_PROP + "authenticator";

    /**
     * The name of the property containing the format of the sub to return in the user info endpoint.
     * 
     * @since 1.23
     */
    public static final String PROP_SUBFORMAT = PREFIX_PROP + "subFormat";

    /**
     * The format of the sub to return in the user info endpoint.
     *
     * @version $Id$
     * @since 1.23
     */
    public enum SubFormat
    {
        /**
         * The full reference (to a void conflict in a multiwiki setup).
         */
        FULL,

        /**
         * The local reference (without the "XWiki" space) for a single wiki setup.
         */
        LOCAL
    }

    /**
     * @return the authenticator to fallback to
     */
    public String getAuthenticator()
    {
        return getProperty(PROP_AUTHENTICATOR, null);
    }

    /**
     * @return the format of the sub to return in the user info endpoint
     * @since 1.23
     */
    public SubFormat getSubMode()
    {
        return getProperty(PROP_SUBFORMAT, SubFormat.FULL);
    }
}
