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
package org.xwiki.contrib.oidc.provider.internal.script;

import java.net.URI;
import java.util.Date;

import org.xwiki.contrib.oidc.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.BaseObjectOIDCConsent;

/**
 * Expose safe OpenID Connect consent metadata.
 * 
 * @version $Id$
 * @since 2.13.0
 */
public class SafeOIDCConsent implements OIDCConsent
{
    private final BaseObjectOIDCConsent consent;

    /**
     * @param consent the stored consent
     */
    public SafeOIDCConsent(BaseObjectOIDCConsent consent)
    {
        this.consent = consent;
    }

    @Override
    public String getId()
    {
        return this.consent.getId();
    }

    @Override
    public String getClientID()
    {
        return this.consent.getClientID();
    }

    @Override
    public URI getRedirectURI()
    {
        return this.consent.getRedirectURI();
    }

    @Override
    public String getAccessTokenValue()
    {
        return this.consent.getAccessTokenValue();
    }

    @Override
    public Date getAccessTokenExpiration()
    {
        return this.consent.getAccessTokenExpiration();
    }

    @Override
    public boolean isEnabled()
    {
        return this.consent.isEnabled();
    }
}
