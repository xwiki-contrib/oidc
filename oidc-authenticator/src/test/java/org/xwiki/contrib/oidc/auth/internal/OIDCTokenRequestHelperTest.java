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

import java.util.Date;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCTokenRequestHelper}.
 *
 * @version $Id$
 */
class OIDCTokenRequestHelperTest
{
    // A date with no milliseconds, since the exp claim of a JWT is in seconds
    private static final Date JWT_EXPIRATION = new Date(4102444800000L);

    private static AccessTokenResponse response(RefreshToken refreshToken, Map<String, Object> parameters)
    {
        return new AccessTokenResponse(new Tokens(new BearerAccessToken(), refreshToken), parameters);
    }

    private static RefreshToken jwtRefreshToken()
    {
        return new RefreshToken(
            new PlainJWT(new JWTClaimsSet.Builder().expirationTime(JWT_EXPIRATION).build()).serialize());
    }

    private static void assertExpiresIn(long lifetime, Date expiration, long before)
    {
        long after = System.currentTimeMillis();

        assertTrue(expiration.getTime() >= before + lifetime * 1000, expiration::toString);
        assertTrue(expiration.getTime() <= after + lifetime * 1000, expiration::toString);
    }

    @Test
    void getRefreshTokenExpirationDateFromRefreshExpiresIn()
    {
        long before = System.currentTimeMillis();

        // The response parameter takes precedence over the JWT exp claim
        Date expiration = OIDCTokenRequestHelper
            .getRefreshTokenExpirationDate(response(jwtRefreshToken(), Map.of("refresh_expires_in", 1800L)));

        assertExpiresIn(1800, expiration, before);
    }

    @Test
    void getRefreshTokenExpirationDateFromRefreshTokenExpiresIn()
    {
        long before = System.currentTimeMillis();

        Date expiration = OIDCTokenRequestHelper.getRefreshTokenExpirationDate(
            response(new RefreshToken("opaque"), Map.of("refresh_token_expires_in", "86400")));

        assertExpiresIn(86400, expiration, before);
    }

    @Test
    void getRefreshTokenExpirationDateFromJWT()
    {
        assertEquals(JWT_EXPIRATION,
            OIDCTokenRequestHelper.getRefreshTokenExpirationDate(response(jwtRefreshToken(), Map.of())));

        // A lifetime of 0 means no expiration for Keycloak, and is not a lifetime
        assertEquals(JWT_EXPIRATION, OIDCTokenRequestHelper
            .getRefreshTokenExpirationDate(response(jwtRefreshToken(), Map.of("refresh_expires_in", 0))));
    }

    @Test
    void getRefreshTokenExpirationDateWhenUnknown()
    {
        assertNull(OIDCTokenRequestHelper.getRefreshTokenExpirationDate(response(null, Map.of())));
        assertNull(
            OIDCTokenRequestHelper.getRefreshTokenExpirationDate(response(new RefreshToken("opaque"), Map.of())));
        assertNull(OIDCTokenRequestHelper.getRefreshTokenExpirationDate(
            response(new RefreshToken("opaque"), Map.of("refresh_expires_in", "notanumber"))));
        assertNull(OIDCTokenRequestHelper.getRefreshTokenExpirationDate(
            response(new RefreshToken("opaque"), Map.of("refresh_expires_in", 0))));
    }

    @Test
    void logRefreshTokenExpiration()
    {
        Logger logger = mock(Logger.class);
        when(logger.isDebugEnabled()).thenReturn(true);

        OIDCTokenRequestHelper.logRefreshTokenExpiration(
            response(new RefreshToken("opaque"), Map.of("refresh_expires_in", 5400)), logger);
        verify(logger).debug(eq("The refresh token expires on [{}], in [{}]"), any(Date.class),
            eq("1 hour 30 minutes"));

        Date pastExpiration = new Date(1000000000000L);
        OIDCTokenRequestHelper.logRefreshTokenExpiration(response(new RefreshToken(
            new PlainJWT(new JWTClaimsSet.Builder().expirationTime(pastExpiration).build()).serialize()), Map.of()),
            logger);
        verify(logger).debug("The refresh token already expired on [{}]", pastExpiration);

        OIDCTokenRequestHelper.logRefreshTokenExpiration(response(new RefreshToken("opaque"), Map.of()), logger);
        verify(logger).debug("The provider did not indicate when the refresh token expires");

        OIDCTokenRequestHelper.logRefreshTokenExpiration(response(null, Map.of()), logger);
        verify(logger).debug("The token response does not contain a refresh token");
    }
}
