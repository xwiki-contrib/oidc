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

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;

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
     * The name of the property containing the format of the sub to return in the user info endpoint.
     * 
     * @since 1.23
     */
    public static final String PROP_SUBFORMAT = PREFIX_PROP + "subFormat";

    /**
     * The name of the property containing the origins allowed to access the provider endpoints meant to be called
     * directly by JavaScript clients (CORS).
     * 
     * @since 2.29.0
     */
    public static final String PROP_CORS_ALLOWEDORIGINS = PREFIX_PROP + "cors.allowedOrigins";

    /**
     * The value used to allow any origin.
     * 
     * @since 2.29.0
     */
    public static final String CORS_ANY_ORIGIN = "*";

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
     * @return the format of the sub to return in the user info endpoint
     * @since 1.23
     */
    public SubFormat getSubMode()
    {
        return getProperty(PROP_SUBFORMAT, SubFormat.FULL);
    }

    /**
     * @return the origins allowed to access the provider endpoints meant to be called directly by JavaScript clients
     *         ({@link #CORS_ANY_ORIGIN} to allow any origin, empty to disable CORS support)
     * @since 2.29.0
     */
    public List<String> getCORSAllowedOrigins()
    {
        // The OpenID Connect specification recommends to support CORS on the userinfo endpoint so allow any origin
        // by default
        if (!this.configuration.containsKey(PROP_CORS_ALLOWEDORIGINS)) {
            return List.of(CORS_ANY_ORIGIN);
        }

        List<?> origins = getProperty(PROP_CORS_ALLOWEDORIGINS, List.class);
        if (origins == null) {
            return List.of();
        }

        return origins.stream().filter(Objects::nonNull).map(origin -> StringUtils.trim(origin.toString()))
            .filter(StringUtils::isNotEmpty).collect(Collectors.toList());
    }
}
