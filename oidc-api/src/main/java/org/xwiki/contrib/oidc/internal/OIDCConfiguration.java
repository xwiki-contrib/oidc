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
package org.xwiki.contrib.oidc.internal;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;

/**
 * Various OpenID Connect configurations commons to both the provider and the authenticator.
 * 
 * @version $Id$
 * @since 1.10
 */
@Component(roles = OIDCConfiguration.class)
@Singleton
public class OIDCConfiguration
{
    /**
     * The prefix used for OpenID Connect configuration properties.
     */
    public static final String PREFIX_PROP = "oidc.";

    /**
     * The name of the claim used to get the groups a user is member of.
     * 
     * @since 1.10
     */
    public static final String PROP_GROUPS_CLAIM = PREFIX_PROP + "groups.claim";

    /**
     * The default name of the claim used to get the groups a user is member of.
     * 
     * @since 1.10
     */
    public static final String DEFAULT_GROUPSCLAIM = "xwiki_groups";

    @Inject
    protected ConfigurationSource configuration;

    /**
     * @param key the name of the property
     * @param valueClass the class of the property
     * @return the property value
     */
    protected <T> T getProperty(String key, Class<T> valueClass)
    {
        // Get property from configuration
        return this.configuration.getProperty(key, valueClass);
    }

    /**
     * @param key the name of the property
     * @param def the default value
     * @return the property value
     */
    protected <T> T getProperty(String key, T def)
    {
        // Get property from configuration
        return this.configuration.getProperty(key, def);
    }

    /**
     * @return the name of the claim used to get the groups a user is member of
     */
    public String getGroupClaim()
    {
        return getProperty(PROP_GROUPS_CLAIM, DEFAULT_GROUPSCLAIM);
    }
}
