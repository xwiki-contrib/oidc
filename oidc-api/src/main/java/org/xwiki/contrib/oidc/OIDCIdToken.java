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

import java.util.Date;
import java.util.List;

/**
 * The OpenID Connect ID token.
 * <p>
 * Related specifications:
 * <ul>
 * <li>OpenID Connect Core 1.0, section 2.
 * </ul>
 * 
 * @version $Id$
 * @since 1.2
 */
public interface OIDCIdToken extends OIDCClaimsSet
{
    /**
     * The id of the XWiki provider instance.
     * 
     * @since 1.3
     */
    String CLAIM_XWIKI_INSTANCE_ID = "xwiki_instance_id";

    /**
     * Gets the ID token issuer. Corresponds to the {@code iss} claim.
     *
     * @return The issuer.
     */
    String getIssuer();

    /**
     * Gets the ID token subject. Corresponds to the {@code sub} claim.
     *
     * @return The subject.
     */
    String getSubject();

    /**
     * Gets the ID token audience. Corresponds to the {@code aud} claim.
     *
     * @return The audience.
     */
    List<String> getAudience();

    /**
     * Gets the ID token expiration time. Corresponds to the {@code exp} claim.
     *
     * @return The expiration time.
     */
    Date getExpirationTime();

    /**
     * Gets the ID token issue time. Corresponds to the {@code iss} claim.
     *
     * @return The issue time.
     */
    Date getIssueTime();

    /**
     * Gets the subject authentication time. Corresponds to the {@code auth_time} claim.
     *
     * @return The authentication time, {@code null} if not specified or parsing failed.
     */
    Date getAuthenticationTime();

    /**
     * Gets the ID token nonce. Corresponds to the {@code nonce} claim.
     *
     * @return The nonce, {@code null} if not specified or parsing failed.
     */
    String getNonce();

    /**
     * Gets the access token hash. Corresponds to the {@code at_hash} claim.
     *
     * @return The access token hash, {@code null} if not specified or parsing failed.
     */
    String getAccessTokenHash();

    /**
     * Gets the authorization code hash. Corresponds to the {@code c_hash} claim.
     *
     * @return The authorization code hash, {@code null} if not specified or parsing failed.
     */
    String getCodeHash();

    /**
     * Gets the Authentication Context Class Reference (ACR). Corresponds to the {@code acr} claim.
     *
     * @return The Authentication Context Class Reference (ACR), {@code null} if not specified or parsing failed.
     */
    String getACR();

    /**
     * Gets the Authentication Methods References (AMRs). Corresponds to the {@code amr} claim.
     *
     * @return The Authentication Methods Reference (AMR) list, {@code null} if not specified or parsing failed.
     */
    List<String> getAMR();

    /**
     * Gets the authorized party for the ID token. Corresponds to the {@code azp} claim.
     *
     * @return The authorized party, {@code null} if not specified or parsing failed.
     */
    String getAuthorizedParty();
}
