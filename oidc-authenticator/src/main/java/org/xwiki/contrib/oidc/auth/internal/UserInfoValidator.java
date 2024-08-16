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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.validators.AbstractJWTValidator;

import net.jcip.annotations.ThreadSafe;

/**
 * Validator of UserInfo JWT tokens issued by an OpenID Provider (OP).
 * <p>
 * Supports processing of UserInfo tokens with the following protection:
 * <ul>
 * <li>UserInfo tokens signed (JWS) with the OP's RSA or EC key, require the OP public JWK set (provided by value or
 * URL) to verify them.
 * <li>UserInfo tokens authenticated with a JWS HMAC, require the client's secret to verify them.
 * <li>Unsecured (plain) UserInfo tokens received at the token endpoint.
 * </ul>
 * <p>
 * Convenience static methods for creating an UserInfo token validator from OpenID Provider metadata or issuer URL, and
 * the registered Relying Party information:
 * <ul>
 * <li>{@link #create(OIDCProviderMetadata, OIDCClientInformation)}
 * <li>{@link #create(Issuer, OIDCClientInformation)}
 * </ul>
 * <p>
 * Related specifications:
 * <ul>
 * <li>OpenID Connect Core 1.0, sections 5.3.2.
 * </ul>
 * 
 * @since 2.11.0
 */
@ThreadSafe
// TODO Use the one from oidc sdk when merged, see
// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/pull-requests/33
public class UserInfoValidator extends AbstractJWTValidator implements ClockSkewAware
{

    /**
     * Creates a new validator for unsecured (plain) UserInfo tokens.
     *
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     */
    public UserInfoValidator(final Issuer expectedIssuer, final ClientID clientID)
    {

        this(expectedIssuer, clientID, (JWSKeySelector) null, null);
    }

    /**
     * Creates a new validator for RSA or EC signed UserInfo tokens where the OpenID Provider's JWK set is specified by
     * value.
     *
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not be {@code null}.
     * @param jwkSet The OpenID Provider JWK set. Must not be {@code null}.
     */
    public UserInfoValidator(final Issuer expectedIssuer, final ClientID clientID, final JWSAlgorithm expectedJWSAlg,
        final JWKSet jwkSet)
    {

        this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableJWKSet(jwkSet)),
            null);
    }

    /**
     * Creates a new validator for RSA or EC signed UserInfo tokens where the OpenID Provider's JWK set is specified by
     * URL.
     *
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not be {@code null}.
     * @param jwkSetURI The OpenID Provider JWK set URL. Must not be {@code null}.
     */
    public UserInfoValidator(final Issuer expectedIssuer, final ClientID clientID, final JWSAlgorithm expectedJWSAlg,
        final URL jwkSetURI)
    {

        this(expectedIssuer, clientID, expectedJWSAlg, jwkSetURI, null);
    }

    /**
     * Creates a new validator for RSA or EC signed UserInfo tokens where the OpenID Provider's JWK set is specified by
     * URL. Permits setting of a specific resource retriever (HTTP client) for the JWK set.
     *
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not be {@code null}.
     * @param jwkSetURI The OpenID Provider JWK set URL. Must not be {@code null}.
     * @param resourceRetriever For retrieving the OpenID Connect Provider JWK set from the specified URL. If
     *            {@code null} the {@link com.nimbusds.jose.util.DefaultResourceRetriever default retriever} will be
     *            used, with preset HTTP connect timeout, HTTP read timeout and entity size limit.
     */
    public UserInfoValidator(final Issuer expectedIssuer, final ClientID clientID, final JWSAlgorithm expectedJWSAlg,
        final URL jwkSetURI, final ResourceRetriever resourceRetriever)
    {

        this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg,
            JWKSourceBuilder.create(jwkSetURI, resourceRetriever).build()), null);
    }

    /**
     * Creates a new validator for HMAC protected UserInfo tokens.
     *
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     * @param expectedJWSAlg The expected HMAC JWS algorithm. Must not be {@code null}.
     * @param clientSecret The client secret. Must not be {@code null}.
     */
    public UserInfoValidator(final Issuer expectedIssuer, final ClientID clientID, final JWSAlgorithm expectedJWSAlg,
        final Secret clientSecret)
    {

        this(expectedIssuer, clientID,
            new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes())), null);
    }

    /**
     * Creates a new UserInfo token validator.
     *
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     * @param jwsKeySelector The key selector for JWS verification, {@code null} if unsecured (plain) UserInfo tokens
     *            are expected.
     * @param jweKeySelector The key selector for JWE decryption, {@code null} if encrypted UserInfo tokens are not
     *            expected.
     */
    public UserInfoValidator(final Issuer expectedIssuer, final ClientID clientID, final JWSKeySelector jwsKeySelector,
        final JWEKeySelector jweKeySelector)
    {

        this(null, expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
    }

    /**
     * Creates a new UserInfo token validator.
     *
     * @param jwtType The expected JWT "typ" (type) header, {@code null} if none.
     * @param expectedIssuer The expected UserInfo token issuer (OpenID Provider). Must not be {@code null}.
     * @param clientID The client ID. Must not be {@code null}.
     * @param jwsKeySelector The key selector for JWS verification, {@code null} if unsecured (plain) UserInfo tokens
     *            are expected.
     * @param jweKeySelector The key selector for JWE decryption, {@code null} if encrypted UserInfo tokens are not
     *            expected.
     */
    public UserInfoValidator(final JOSEObjectType jwtType, final Issuer expectedIssuer, final ClientID clientID,
        final JWSKeySelector jwsKeySelector, final JWEKeySelector jweKeySelector)
    {

        super(jwtType, expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
    }

    /**
     * Validates the specified UserInfo token.
     *
     * @param userInfoToken The UserInfo token. Must not be {@code null}.
     * @return The claims set of the verified UserInfo token.
     * @throws BadJOSEException If the UserInfo token is invalid or expired.
     * @throws JOSEException If an internal JOSE exception was encountered.
     */
    public UserInfo validate(final JWT userInfoToken) throws BadJOSEException, JOSEException
    {

        if (userInfoToken instanceof PlainJWT) {
            return validate((PlainJWT) userInfoToken);
        } else if (userInfoToken instanceof SignedJWT) {
            return validate((SignedJWT) userInfoToken);
        } else if (userInfoToken instanceof EncryptedJWT) {
            return validate((EncryptedJWT) userInfoToken);
        } else {
            throw new JOSEException("Unexpected JWT type: " + userInfoToken.getClass());
        }
    }

    /**
     * Verifies the specified unsecured (plain) UserInfo token.
     *
     * @param userInfoToken The UserInfo token. Must not be {@code null}.
     * @return The claims set of the verified UserInfo token.
     * @throws BadJOSEException If the UserInfo token is invalid or expired.
     * @throws JOSEException If an internal JOSE exception was encountered.
     */
    private UserInfo validate(final PlainJWT userInfoToken) throws BadJOSEException, JOSEException
    {

        if (getJWSKeySelector() != null) {
            throw new BadJWTException("Signed UserInfo token expected");
        }

        JWTClaimsSet jwtClaimsSet;

        try {
            jwtClaimsSet = userInfoToken.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new BadJWTException(e.getMessage(), e);
        }

        return toUserInfo(jwtClaimsSet);
    }

    private JWTClaimsSetVerifier<SecurityContext> createJWTClaimsSetVerifier()
    {
        return new DefaultJWTClaimsVerifier<>(Collections.singleton(getClientID().getValue()),
            new JWTClaimsSet.Builder().issuer(getExpectedIssuer().getValue()).build(), Collections.<String>emptySet(),
            Collections.<String>emptySet());
    }

    /**
     * Verifies the specified signed UserInfo token.
     *
     * @param userInfoToken The UserInfo token. Must not be {@code null}.
     * @return The claims set of the verified UserInfo.
     * @throws BadJOSEException If the UserInfo token is invalid or expired.
     * @throws JOSEException If an internal JOSE exception was encountered.
     */
    private UserInfo validate(final SignedJWT userInfoToken) throws BadJOSEException, JOSEException
    {

        if (getJWSKeySelector() == null) {
            throw new BadJWTException("Verification of signed JWTs not configured");
        }

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        if (getExpectedJWTType() != null) {
            jwtProcessor
                .setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier(Collections.singleton(getExpectedJWTType())));
        }
        jwtProcessor.setJWSKeySelector(getJWSKeySelector());
        jwtProcessor.setJWTClaimsSetVerifier(createJWTClaimsSetVerifier());
        JWTClaimsSet jwtClaimsSet = jwtProcessor.process(userInfoToken, null);
        return toUserInfo(jwtClaimsSet);
    }

    /**
     * Verifies the specified signed and encrypted UserInfo token.
     *
     * @param userInfoToken The UserInfo token. Must not be {@code null}.
     * @return The claims set of the verified UserInfo token.
     * @throws BadJOSEException If the UserInfo token is invalid or expired.
     * @throws JOSEException If an internal JOSE exception was encountered.
     */
    private UserInfo validate(final EncryptedJWT userInfoToken) throws BadJOSEException, JOSEException
    {

        if (getJWEKeySelector() == null) {
            throw new BadJWTException("Decryption of JWTs not configured");
        }
        if (getJWSKeySelector() == null) {
            throw new BadJWTException("Verification of signed JWTs not configured");
        }

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(getJWSKeySelector());
        jwtProcessor.setJWEKeySelector(getJWEKeySelector());
        jwtProcessor.setJWTClaimsSetVerifier(createJWTClaimsSetVerifier());

        JWTClaimsSet jwtClaimsSet = jwtProcessor.process(userInfoToken, null);

        return toUserInfo(jwtClaimsSet);
    }

    /**
     * Converts a JWT claims set to an UserInfo claims set.
     *
     * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
     * @return The UserInfo claims set.
     * @throws JOSEException If conversion failed.
     */
    private static UserInfo toUserInfo(final JWTClaimsSet jwtClaimsSet) throws JOSEException
    {
        return new UserInfo(jwtClaimsSet);
    }

    /**
     * Creates a key selector for JWS verification.
     *
     * @param opMetadata The OpenID Provider metadata. Must not be {@code null}.
     * @param clientInfo The Relying Party metadata. Must not be {@code null}.
     * @return The JWS key selector.
     * @throws GeneralException If the supplied OpenID Provider metadata or Relying Party metadata are missing a
     *             required parameter or inconsistent.
     */
    protected static JWSKeySelector createJWSKeySelector(final OIDCProviderMetadata opMetadata,
        final OIDCClientInformation clientInfo) throws GeneralException
    {

        final JWSAlgorithm expectedJWSAlg = clientInfo.getOIDCMetadata().getUserInfoJWSAlg();

        if (opMetadata.getUserInfoJWSAlgs() == null) {
            throw new GeneralException("Missing OpenID Provider userinfo_signing_alg_values_supported parameter");
        }

        if (!opMetadata.getUserInfoJWSAlgs().contains(expectedJWSAlg)) {
            throw new GeneralException("The OpenID Provider doesn't support " + expectedJWSAlg + " UserInfo tokens");
        }

        if (Algorithm.NONE.equals(expectedJWSAlg)) {
            // Skip creation of JWS key selector, plain UserInfo tokens expected
            return null;

        } else if (JWSAlgorithm.Family.RSA.contains(expectedJWSAlg)
            || JWSAlgorithm.Family.EC.contains(expectedJWSAlg)) {

            URL jwkSetURL;
            try {
                jwkSetURL = opMetadata.getJWKSetURI().toURL();
            } catch (MalformedURLException e) {
                throw new GeneralException("Invalid jwk set URI: " + e.getMessage(), e);
            }
            JWKSource jwkSource = JWKSourceBuilder.create(jwkSetURL).build(); // TODO specify HTTP response limits

            return new JWSVerificationKeySelector(expectedJWSAlg, jwkSource);

        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(expectedJWSAlg)) {

            Secret clientSecret = clientInfo.getSecret();
            if (clientSecret == null) {
                throw new GeneralException("Missing client secret");
            }
            return new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes()));

        } else {
            throw new GeneralException("Unsupported JWS algorithm: " + expectedJWSAlg);
        }
    }

    /**
     * Creates a key selector for JWE decryption.
     *
     * @param opMetadata The OpenID Provider metadata. Must not be {@code null}.
     * @param clientInfo The Relying Party metadata. Must not be {@code null}.
     * @param clientJWKSource The client private JWK source, {@code null} if encrypted UserInfo tokens are not expected.
     * @return The JWE key selector.
     * @throws GeneralException If the supplied OpenID Provider metadata or Relying Party metadata are missing a
     *             required parameter or inconsistent.
     */
    protected static JWEKeySelector createJWEKeySelector(final OIDCProviderMetadata opMetadata,
        final OIDCClientInformation clientInfo, final JWKSource clientJWKSource) throws GeneralException
    {

        final JWEAlgorithm expectedJWEAlg = clientInfo.getOIDCMetadata().getUserInfoJWEAlg();
        final EncryptionMethod expectedJWEEnc = clientInfo.getOIDCMetadata().getUserInfoJWEEnc();

        if (expectedJWEAlg == null) {
            // Encrypted UserInfo tokens not expected
            return null;
        }

        if (expectedJWEEnc == null) {
            throw new GeneralException("Missing required UserInfo token JWE encryption method for " + expectedJWEAlg);
        }

        if (opMetadata.getUserInfoJWEAlgs() == null || !opMetadata.getUserInfoJWEAlgs().contains(expectedJWEAlg)) {
            throw new GeneralException("The OpenID Provider doesn't support " + expectedJWEAlg + " UserInfo tokens");
        }

        if (opMetadata.getUserInfoJWEEncs() == null || !opMetadata.getUserInfoJWEEncs().contains(expectedJWEEnc)) {
            throw new GeneralException(
                "The OpenID Provider doesn't support " + expectedJWEAlg + " / " + expectedJWEEnc + " UserInfo tokens");
        }

        return new JWEDecryptionKeySelector(expectedJWEAlg, expectedJWEEnc, clientJWKSource);
    }

    /**
     * Creates a new UserInfo token validator for the specified OpenID Provider metadata and OpenID Relying Party
     * registration.
     *
     * @param opMetadata The OpenID Provider metadata. Must not be {@code null}.
     * @param clientInfo The OpenID Relying Party registration. Must not be {@code null}.
     * @param clientJWKSource The client private JWK source, {@code null} if encrypted UserInfo tokens are not expected.
     * @return The UserInfo token validator.
     * @throws GeneralException If the supplied OpenID Provider metadata or Relying Party metadata are missing a
     *             required parameter or inconsistent.
     */
    public static UserInfoValidator create(final OIDCProviderMetadata opMetadata,
        final OIDCClientInformation clientInfo, final JWKSource clientJWKSource) throws GeneralException
    {

        // Create JWS key selector, unless id_token alg = none
        final JWSKeySelector jwsKeySelector = createJWSKeySelector(opMetadata, clientInfo);

        // Create JWE key selector if encrypted UserInfo tokens are expected
        final JWEKeySelector jweKeySelector = createJWEKeySelector(opMetadata, clientInfo, clientJWKSource);

        return new UserInfoValidator(opMetadata.getIssuer(), clientInfo.getID(), jwsKeySelector, jweKeySelector);
    }

    /**
     * Creates a new UserInfo token validator for the specified OpenID Provider metadata and OpenID Relying Party
     * registration.
     *
     * @param opMetadata The OpenID Provider metadata. Must not be {@code null}.
     * @param clientInfo The OpenID Relying Party registration. Must not be {@code null}.
     * @return The UserInfo token validator.
     * @throws GeneralException If the supplied OpenID Provider metadata or Relying Party metadata are missing a
     *             required parameter or inconsistent.
     */
    public static UserInfoValidator create(final OIDCProviderMetadata opMetadata,
        final OIDCClientInformation clientInfo) throws GeneralException
    {

        return create(opMetadata, clientInfo, null);
    }

    /**
     * Creates a new UserInfo token validator for the specified OpenID Provider, which must publish its metadata at
     * {@code [issuer-url]/.well-known/openid-configuration}.
     *
     * @param opIssuer The OpenID Provider issuer identifier. Must not be {@code null}.
     * @param clientInfo The OpenID Relying Party registration. Must not be {@code null}.
     * @return The UserInfo token validator.
     * @throws GeneralException If the resolved OpenID Provider metadata is invalid.
     * @throws IOException On a HTTP exception.
     */
    public static UserInfoValidator create(final Issuer opIssuer, final OIDCClientInformation clientInfo)
        throws GeneralException, IOException
    {

        return create(opIssuer, clientInfo, null, 0, 0);
    }

    /**
     * Creates a new UserInfo token validator for the specified OpenID Provider, which must publish its metadata at
     * {@code [issuer-url]/.well-known/openid-configuration}.
     *
     * @param opIssuer The OpenID Provider issuer identifier. Must not be {@code null}.
     * @param clientInfo The OpenID Relying Party registration. Must not be {@code null}.
     * @param clientJWKSource The client private JWK source, {@code null} if encrypted UserInfo tokens are not expected.
     * @param connectTimeout The HTTP connect timeout, in milliseconds. Zero implies no timeout. Must not be negative.
     * @param readTimeout The HTTP response read timeout, in milliseconds. Zero implies no timeout. Must not be
     *            negative.
     * @return The UserInfo token validator.
     * @throws GeneralException If the resolved OpenID Provider metadata is invalid.
     * @throws IOException On a HTTP exception.
     */
    public static UserInfoValidator create(final Issuer opIssuer, final OIDCClientInformation clientInfo,
        final JWKSource clientJWKSource, final int connectTimeout, final int readTimeout)
        throws GeneralException, IOException
    {

        OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(opIssuer, connectTimeout, readTimeout);

        return create(opMetadata, clientInfo, clientJWKSource);
    }
}
