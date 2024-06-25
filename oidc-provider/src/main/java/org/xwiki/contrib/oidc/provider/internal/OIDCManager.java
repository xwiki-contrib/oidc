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
package org.xwiki.contrib.oidc.provider.internal;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.joda.time.LocalDateTime;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.contrib.oidc.OIDCIdToken;
import org.xwiki.contrib.oidc.provider.internal.session.OIDCClients;
import org.xwiki.contrib.oidc.provider.internal.session.ProviderOIDCSessions;
import org.xwiki.contrib.oidc.provider.internal.session.ProviderOIDCSessions.ProviderOIDCSession;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.contrib.oidc.provider.internal.util.ContentResponse;
import org.xwiki.environment.Environment;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.template.TemplateManager;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.xpn.xwiki.XWikiContext;

/**
 * Main utility for OIDC provider.
 * 
 * @version $Id$
 */
@Component(roles = OIDCManager.class)
@Singleton
public class OIDCManager implements Initializable, JWKSetSource<SecurityContext>
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("compact")
    private EntityReferenceSerializer<String> compactReferenceSerializer;

    @Inject
    private TemplateManager templates;

    @Inject
    private InstanceIdManager instance;

    @Inject
    private Environment environment;

    @Inject
    private OIDCStore oidcStore;

    @Inject
    private ProviderOIDCSessions sessions;

    @Inject
    private OIDCClients clients;

    @Inject
    private Execution execution;

    @Inject
    private Logger logger;

    private RSASSASigner signer;

    private JWKSource<SecurityContext> privateJWLSource = new JWKSetBasedJWKSource<>(this);

    private JWKSet privateJWKSet;

    private JWKSet publicJWKSet;

    private RSAKey privateRSAKey;

    private RSAKey publicRSAKey;

    private JWSHeader header;

    @Override
    public void initialize() throws InitializationException
    {
        File permdir = this.environment.getPermanentDirectory();

        if (permdir != null) {
            File jwkSetFile = new File(permdir, "oidc/jwkSet.json");

            if (jwkSetFile.exists()) {
                try {
                    loadKeys(jwkSetFile);
                } catch (Exception e) {
                    this.logger.warn("Failed to load key pair, generating a new one: {}",
                        ExceptionUtils.getRootCauseMessage(e));
                }
            }

            if (this.privateRSAKey == null) {
                try {
                    generateKeys(jwkSetFile);
                } catch (Exception e) {
                    this.logger.warn("Failed to generate a RSA key, tokens won't be signed: {}",
                        ExceptionUtils.getRootCauseMessage(e));
                }
            }

            if (this.privateRSAKey != null) {
                try {
                    this.signer = new RSASSASigner(this.privateRSAKey);
                    this.header = new JWSHeader(JWSAlgorithm.RS256, null, null, null, null, this.publicRSAKey,
                        this.privateRSAKey.getX509CertURL(), this.privateRSAKey.getX509CertThumbprint(),
                        this.privateRSAKey.getX509CertSHA256Thumbprint(), this.privateRSAKey.getX509CertChain(),
                        this.privateRSAKey.getKeyID(), true, null, null);
                } catch (JOSEException e) {
                    this.logger.warn("Failed to generate a signer, tokens won't be signed: {}",
                        ExceptionUtils.getRootCauseMessage(e));
                }
            }
        }
    }

    private void loadKeys(File jwkSetFile) throws IOException, java.text.ParseException
    {
        this.privateJWKSet = JWKSet.load(jwkSetFile);

        if (CollectionUtils.isNotEmpty(this.privateJWKSet.getKeys())) {
            List<JWK> publicKeys = new ArrayList<>(this.privateJWKSet.getKeys().size());

            for (JWK key : this.privateJWKSet.getKeys()) {
                if (key instanceof RSAKey) {
                    this.privateRSAKey = (RSAKey) key;
                    this.publicRSAKey = this.privateRSAKey.toPublicJWK();
                    publicKeys.add(this.publicRSAKey);
                }
            }

            this.publicJWKSet = new JWKSet(publicKeys);
        }
    }

    private void generateKeys(File jwkSetFile) throws JOSEException
    {
        this.privateRSAKey = new RSAKeyGenerator(2048).keyID(RandomStringUtils.randomAlphanumeric(4))
            .keyUse(KeyUse.SIGNATURE).generate();
        this.publicRSAKey = this.privateRSAKey.toPublicJWK();
        this.privateJWKSet = new JWKSet(this.privateRSAKey);
        this.publicJWKSet = new JWKSet(this.publicRSAKey);

        String json = this.privateJWKSet.toString(false);
        try {
            FileUtils.write(jwkSetFile, json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            this.logger.warn("Failed to save JWK set, it will be lost at next restart: {}",
                ExceptionUtils.getRootCauseMessage(e));
        }
    }

    /**
     * @return the JWKSet
     * @since 1.24
     */
    public JWKSet getPublicJWKSet()
    {
        return this.publicJWKSet;
    }

    @Override
    public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context)
        throws KeySourceException
    {
        return this.privateJWKSet;
    }

    public JWKSource<SecurityContext> getJWKSource()
    {
        return this.privateJWLSource;
    }

    @Override
    public void close() throws IOException
    {
        // Nothing to do
    }

    /**
     * @return the issuer
     * @throws MalformedURLException when failing to create the issuer
     * @throws URISyntaxException when failing to create the issuer
     */
    public Issuer getIssuer() throws MalformedURLException, URISyntaxException
    {
        return new Issuer(createBaseEndPointURI());
    }

    /**
     * Generate and return an external {@link URI} for passed endpoint in the current instance.
     * 
     * @param endpoint the endpoint
     * @return the {@link URI}
     * @throws MalformedURLException when failing to get server URL
     * @throws URISyntaxException when failing to create the URI
     */
    public URI createEndPointURI(String endpoint) throws MalformedURLException, URISyntaxException
    {
        return createEndPointURI(createBaseEndPointURI(), endpoint);
    }

    /**
     * @return the base URL
     * @throws MalformedURLException when failing to get server URL
     */
    public String createBaseEndPointURI() throws MalformedURLException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        StringBuilder base = new StringBuilder();

        base.append(xcontext.getURLFactory().getServerURL(xcontext));

        if (base.charAt(base.length() - 1) != '/') {
            base.append('/');
        }

        String webAppPath = xcontext.getWiki().getWebAppPath(xcontext);
        if (!webAppPath.equals("/")) {
            base.append(webAppPath);
        }

        base.append("oidc");

        return base.toString();
    }

    /**
     * Generate and return an external {@link URI} for passed endpoint in the passed instance.
     * 
     * @param base target instance
     * @param endpoint the endpoint
     * @return the {@link URI}
     * @throws URISyntaxException when failing to create the URI
     */
    public URI createEndPointURI(String base, String endpoint) throws URISyntaxException
    {
        StringBuilder uri = new StringBuilder(base);

        if (!base.endsWith("/")) {
            uri.append('/');
        }

        uri.append(endpoint);

        return new URI(uri.toString());
    }

    /**
     * Generate an OIDC ID Token.
     * 
     * @param clientID the client id
     * @param userReference the reference of the user
     * @param nonce the nonce
     * @param claims the custom fields to return
     * @return the id token
     * @throws MalformedURLException when failing to create the issuer
     * @throws URISyntaxException when failing to create the issuer
     * @since 2.4.0
     */
    public IDTokenClaimsSet createdIdToken(ClientID clientID, DocumentReference userReference, Nonce nonce,
        ClaimsSetRequest claims) throws MalformedURLException, URISyntaxException
    {
        Issuer issuer = getIssuer();
        Subject subject = this.oidcStore.getSubject(userReference);
        List<Audience> audiences =
            clientID != null ? Arrays.asList(new Audience(clientID)) : Collections.<Audience>emptyList();

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime now1year = now.plusYears(1);

        IDTokenClaimsSet idTokenClaimSet =
            new IDTokenClaimsSet(issuer, subject, audiences, now1year.toDate(), now.toDate());

        idTokenClaimSet.setNonce(nonce);

        // Add custom claims
        if (claims != null) {
            for (Entry claim : claims.getEntries()) {
                switch (claim.getClaimName()) {
                    case OIDCIdToken.CLAIM_XWIKI_INSTANCE_ID:
                        idTokenClaimSet.setClaim(OIDCIdToken.CLAIM_XWIKI_INSTANCE_ID, this.instance.getInstanceId());
                        break;

                    default:
                        break;
                }
            }
        }

        return idTokenClaimSet;
    }

    /**
     * Sign the token.
     * 
     * @param token the token to sign
     * @return the signed token
     * @throws ParseException when failing to parse the id token
     * @since 2.4.0
     */
    public JWT signToken(ClaimsSet token) throws ParseException
    {
        JWTClaimsSet jwtClaimsSet = token.toJWTClaimsSet();

        // Convert to JWT
        if (this.signer != null) {
            SignedJWT signedJWT = new SignedJWT(this.header, jwtClaimsSet);

            try {
                signedJWT.sign(this.signer);

                return signedJWT;
            } catch (JOSEException e) {
                this.logger.warn("Failed to sign the id token, returning a plain id token: {}",
                    ExceptionUtils.getRootCauseMessage(e));
            }
        }

        // Fallback on plain JWT in case of problem
        return new PlainJWT(jwtClaimsSet);
    }

    /**
     * Run a template and generate a HTML content response.
     * 
     * @param templateName the name of the template
     * @return the HTML content response
     * @throws Exception when failing to execute the template
     */
    public Response executeTemplate(String templateName) throws Exception
    {
        String html = this.templates.render(templateName);

        return new ContentResponse(ContentResponse.CONTENTTYPE_HTML, html, HTTPResponse.SC_OK);
    }

    public void executeTemplate(String templateName, HttpServletResponse servletResponse) throws Exception
    {
        Response response = executeTemplate(templateName);

        ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
    }

    /**
     * @since 2.4.0
     */
    public void logoutSessions(DocumentReference userReference)
    {
        Subject subject = this.oidcStore.getSubject(userReference);

        // Logout the user from all known clients
        Set<ProviderOIDCSession> subjectSessions = this.sessions.removeSessions(subject);
        for (ProviderOIDCSession sessoin : subjectSessions) {
            try {
                Date iat = new Date();
                Date exp = DateUtils.addMonths(iat, 1);

                // Create a logout token
                LogoutTokenClaimsSet logoutToken = new LogoutTokenClaimsSet(getIssuer(), sessoin.getSubject(),
                    Arrays.asList(new Audience(sessoin.getClientID())), new Date(), exp, new JWTID(), null);

                // Send a logout notification
                this.clients.logout(sessoin.getClientID(), signToken(logoutToken));
            } catch (Exception e) {
                this.logger.error("Failed to logout user with subject [{}] on client [{}]", subject,
                    sessoin.getClientID(), e);
            }
        }
    }

    /**
     * @since 2.4.0
     */
    public void redirect(String location, boolean safe) throws IOException
    {
        if (safe) {
            // Bypass the allowed domain protection, since the URL is safe
            ExecutionContext executionContext = this.execution.getContext();
            if (executionContext != null) {
                executionContext.setProperty("bypassDomainSecurityCheck", true);
            }
        }

        // Redirect to the provider
        XWikiContext xcontext = this.xcontextProvider.get();
        xcontext.getResponse().sendRedirect(location);
        xcontext.setFinished(true);
    }
}
