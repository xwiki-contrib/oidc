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
package org.xwiki.contrib.oidc.auth.internal;

import org.xwiki.contrib.oidc.OIDCAddress;

import com.nimbusds.openid.connect.sdk.claims.Address;

/**
 * Nimbus SDK based implementation of {@link OIDCAddress}.
 * 
 * @version $Id$
 * @since 1.2
 */
public class NimbusOIDCAddress extends NumbusOIDCClaimsSet<Address> implements OIDCAddress
{
    /**
     * @param address the Nimbus SDK address
     */
    public NimbusOIDCAddress(Address address)
    {
        super(address);
    }

    @Override
    public String getFormatted()
    {
        return this.claims.getFormatted();
    }

    @Override
    public String getStreetAddress()
    {
        return this.claims.getStreetAddress();
    }

    @Override
    public String getLocality()
    {
        return this.claims.getLocality();
    }

    @Override
    public String getRegion()
    {
        return this.claims.getRegion();
    }

    @Override
    public String getPostalCode()
    {
        return this.claims.getPostalCode();
    }

    @Override
    public String getCountry()
    {
        return this.claims.getCountry();
    }
}
