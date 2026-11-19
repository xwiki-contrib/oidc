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

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Objects;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders.ClientProvider;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.CommonClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

/**
 * Validates the ID tokens sent by the OpenID Connect provider to the authenticator.
 *
 * @version $Id$
 * @since 2.31.0
 */
@Component(roles = OIDCIdTokenValidator.class)
@Singleton
public class OIDCIdTokenValidator
{
    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCManager manager;

    @Inject
    private Logger logger;

    /**
     * Parses and validates an ID token received directly from the provider token endpoint (at authentication or when
     * refreshing the access token).
     * <p>
     * When the provider metadata is available, the signature, the issuer, the audience and the expiration of the ID
     * token are validated. No nonce is expected, since none is sent to the token endpoint. When the provider metadata
     * is not available, the ID token is only parsed: it comes directly from the token endpoint, so the TLS validation
     * of the server is used in place of the signature validation, as allowed by OpenID Connect Core 1.0 section
     * 3.1.3.7.
     *
     * @param token the ID token sent by the token endpoint
     * @return the claims of the ID token
     * @throws BadJOSEException when the ID token is invalid
     * @throws JOSEException when failing to process the ID token (for example to decrypt it)
     * @throws GeneralException when failing to get the provider metadata or to parse the ID token claims
     * @throws IOException when failing to get the provider metadata
     * @throws URISyntaxException when failing to get the provider metadata
     * @throws java.text.ParseException when failing to parse the ID token claims
     */
    public IDTokenClaimsSet validateTokenEndpointIdToken(JWT token) throws BadJOSEException, JOSEException,
        GeneralException, IOException, URISyntaxException, java.text.ParseException
    {
        IDTokenClaimsSet idToken = validate(token, null);
        if (idToken != null) {
            return idToken;
        }

        this.logger.debug("No provider available in the configuration."
            + " Skipping id token validation and assuming it's not encrypted,"
            + " because it's not possible to access the provider metadata and keys to validate the id token.");

        return new IDTokenClaimsSet(token.getJWTClaimsSet());
    }

    /**
     * Validates an ID token received in the authorization response (implicit and hybrid flows), through the browser.
     * <p>
     * Validating the signature is mandatory for such an ID token, so it's only accepted when the provider metadata (and
     * keys) is available.
     *
     * @param token the ID token sent in the authorization response
     * @param nonce the nonce sent in the authorization request
     * @return the claims of the ID token, or {@code null} when it cannot be validated because the provider metadata is
     *     not available
     * @throws BadJOSEException when the ID token is invalid
     * @throws JOSEException when failing to process the ID token (for example to decrypt it)
     * @throws GeneralException when failing to get the provider metadata
     * @throws IOException when failing to get the provider metadata
     * @throws URISyntaxException when failing to get the provider metadata
     */
    public IDTokenClaimsSet validateAuthorizationResponseIdToken(JWT token, Nonce nonce)
        throws BadJOSEException, JOSEException, GeneralException, IOException, URISyntaxException
    {
        return validate(token, nonce);
    }

    /**
     * Checks that a new ID token received when refreshing the access token describes the same authentication as the
     * current one, as required by OpenID Connect Core 1.0 section 12.2.
     *
     * @param newIdToken the new ID token, already validated with {@link #validateTokenEndpointIdToken(JWT)}
     * @param currentIdToken the ID token currently associated with the session, {@code null} if there is none
     * @throws BadJWTException when the new ID token does not describe the same authentication as the current one, or
     *     when there is no current ID token to compare it with
     */
    public void validateRefreshedIdToken(IDTokenClaimsSet newIdToken, IDTokenClaimsSet currentIdToken)
        throws BadJWTException
    {
        if (currentIdToken == null) {
            throw new BadJWTException("There is no current ID token to compare the new one with");
        }

        checkSameClaim(ClaimsSet.ISS_CLAIM_NAME, currentIdToken.getIssuer(), newIdToken.getIssuer());
        checkSameClaim(CommonClaimsSet.SUB_CLAIM_NAME, currentIdToken.getSubject(), newIdToken.getSubject());
        checkSameClaim(ClaimsSet.AUD_CLAIM_NAME, new HashSet<>(currentIdToken.getAudience()),
            new HashSet<>(newIdToken.getAudience()));
        checkSameClaim(IDTokenClaimsSet.AZP_CLAIM_NAME, currentIdToken.getAuthorizedParty(),
            newIdToken.getAuthorizedParty());
        // The authentication time is optional in the new ID token, but must be the original one when present
        if (newIdToken.getAuthenticationTime() != null) {
            checkSameClaim(IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME, currentIdToken.getAuthenticationTime(),
                newIdToken.getAuthenticationTime());
        }
    }

    /**
     * @return the validated claims, or {@code null} when the provider metadata needed to validate the ID token is not
     *     available
     */
    private IDTokenClaimsSet validate(JWT token, Nonce nonce)
        throws BadJOSEException, JOSEException, GeneralException, IOException, URISyntaxException
    {
        ClientProvider clientProvider = this.configuration.getClientProvider();
        if (clientProvider == null) {
            return null;
        }

        return IDTokenValidator.create(clientProvider.getMetadata(),
            this.configuration.createClientInformation(token), this.manager.getJWKSource()).validate(token, nonce);
    }

    private static void checkSameClaim(String claimName, Object currentValue, Object newValue) throws BadJWTException
    {
        if (!Objects.equals(currentValue, newValue)) {
            throw new BadJWTException(
                String.format("The [%s] claim is not the same as in the current ID token", claimName));
        }
    }
}
