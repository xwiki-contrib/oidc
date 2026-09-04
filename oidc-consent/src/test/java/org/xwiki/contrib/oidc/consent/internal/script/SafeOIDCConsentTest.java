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
package org.xwiki.contrib.oidc.consent.internal.script;

import java.net.URI;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.consent.internal.store.BaseObjectOIDCConsent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link SafeOIDCConsent}.
 *
 * @version $Id$
 */
class SafeOIDCConsentTest
{
    private final BaseObjectOIDCConsent consent = mock(BaseObjectOIDCConsent.class);

    private final SafeOIDCConsent safeConsent = new SafeOIDCConsent(this.consent);

    @Test
    void getId()
    {
        when(this.consent.getId()).thenReturn("id");

        assertEquals("id", this.safeConsent.getId());
    }

    @Test
    void getVersion()
    {
        when(this.consent.getVersion()).thenReturn(2);

        assertEquals(2, this.safeConsent.getVersion());
    }

    @Test
    void getClientID()
    {
        when(this.consent.getClientID()).thenReturn("clientid");

        assertEquals("clientid", this.safeConsent.getClientID());
    }

    @Test
    void getRedirectURI()
    {
        when(this.consent.getRedirectURI()).thenReturn(URI.create("http://host/redirect"));

        assertEquals(URI.create("http://host/redirect"), this.safeConsent.getRedirectURI());
    }

    @Test
    void getAccessTokenValue()
    {
        when(this.consent.getAccessTokenValue()).thenReturn("value");

        assertEquals("value", this.safeConsent.getAccessTokenValue());
    }

    @Test
    void getAccessTokenExpiration()
    {
        when(this.consent.getAccessTokenExpiration()).thenReturn(new Date(42));

        assertEquals(new Date(42), this.safeConsent.getAccessTokenExpiration());
    }

    @Test
    void isEnabled()
    {
        when(this.consent.isEnabled()).thenReturn(true);

        assertTrue(this.safeConsent.isEnabled());

        when(this.consent.isEnabled()).thenReturn(false);

        assertFalse(this.safeConsent.isEnabled());
    }
}
