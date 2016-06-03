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
package org.xwiki.contrib.oidc;

/**
 * The OpenID Connection address.
 * <p>
 * Related specifications:
 * <ul>
 * <li>OpenID Connect Core 1.0, section 5.1.1.
 * </ul>
 * 
 * @version $Id$
 * @since 1.2
 */
public interface OIDCAddress extends OIDCClaimsSet
{
    /**
     * Gets the full mailing address, formatted for display or use with a mailing label. May contain newlines.
     * Corresponds to the {@code formatted} claim.
     *
     * @return The full mailing address, {@code null} if not specified.
     */
    String getFormatted();

    /**
     * Gets the full street address component, which may include house number, street name, PO BOX, and multi-line
     * extended street address information. May contain newlines. Corresponds to the {@code street_address} claim.
     *
     * @return The full street address component, {@code null} if not specified.
     */
    String getStreetAddress();

    /**
     * Gets the city or locality component. Corresponds to the {@code locality} claim, with no language tag.
     *
     * @return The city or locality component, {@code null} if not specified.
     */
    String getLocality();

    /**
     * Gets the state, province, prefecture or region component. Corresponds to the {@code region} claim.
     *
     * @return The state, province, prefecture or region component, {@code null} if not specified.
     */
    String getRegion();

    /**
     * Gets the zip code or postal code component. Corresponds to the {@code postal_code} claim.
     *
     * @return The zip code or postal code component, {@code null} if not specified.
     */
    String getPostalCode();

    /**
     * Gets the country name component. Corresponds to the {@code country} claim.
     *
     * @return The country name component, {@code null} if not specified.
     */
    String getCountry();
}
