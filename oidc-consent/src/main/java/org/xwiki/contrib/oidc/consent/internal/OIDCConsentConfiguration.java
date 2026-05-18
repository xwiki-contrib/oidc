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
package org.xwiki.contrib.oidc.consent.internal;

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.internal.OIDCConfiguration;

/**
 * Various OpenID Connect authenticator configurations.
 * 
 * @version $Id$
 * @since 2.21.0
 */
@Component(roles = OIDCConsentConfiguration.class)
@Singleton
public class OIDCConsentConfiguration extends OIDCConfiguration
{
    /**
     * The prefix used for Token Authenticator configuration properties.
     */
    public static final String PREFIX_PROP = OIDCConfiguration.PREFIX_PROP + "consent.";

    /**
     * The name of the property indicating if it's allowed to create consents from the UI.
     */
    public static final String PROP_CREATE_CONSENT_ENABLED = PREFIX_PROP + "createConsentEnabled";

    /**
     * @return true if it's allowed to create consents from the UI, false if not, null if the property is not set
     */
    public Boolean isCreateTokenEnabled()
    {
        return getProperty(PROP_CREATE_CONSENT_ENABLED, Boolean.class);
    }
}
