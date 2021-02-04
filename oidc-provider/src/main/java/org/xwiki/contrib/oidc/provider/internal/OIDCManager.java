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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.joda.time.LocalDateTime;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.contrib.oidc.OIDCIdToken;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration.SubFormat;
import org.xwiki.contrib.oidc.provider.internal.util.ContentResponse;
import org.xwiki.environment.Environment;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.template.TemplateManager;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.XWikiURLFactory;

/**
 * Main utility for OIDC provider.
 * 
 * @version $Id$
 */
@Component(roles = OIDCManager.class)
@Singleton
public class OIDCManager implements Initializable
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private EntityReferenceSerializer<String> referenceSerializer;

    @Inject
    @Named("compact")
    private EntityReferenceSerializer<String> compactReferenceSerializer;

    @Inject
    private TemplateManager templates;

    @Inject
    private InstanceIdManager instance;

    @Inject
    private OIDCProviderConfiguration configuration;

    @Inject
    private Environment environment;

    @Inject
    private Logger logger;

    private RSASSASigner signer;

    private JWKSet jwkSet;

    private RSAKey rsaKey;

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

            if (this.rsaKey == null) {
                try {
                    generateKeys(jwkSetFile);
                } catch (Exception e) {
                    this.logger.warn("Failed to generate a RSA key, tokens won't be signed: {}",
                        ExceptionUtils.getRootCauseMessage(e));
                }
            }

            if (this.rsaKey != null) {
                try {
                    this.signer = new RSASSASigner(this.rsaKey);
                    this.header =
                        new JWSHeader(JWSAlgorithm.RS256, null, null, null, null, this.rsaKey, this.rsaKey.getX509CertURL(),
                            this.rsaKey.getX509CertThumbprint(), this.rsaKey.getX509CertSHA256Thumbprint(),
                            this.rsaKey.getX509CertChain(), this.rsaKey.getKeyID(), true, null, null);
                } catch (JOSEException e) {
                    this.logger.warn("Failed to generate a signer, tokens won't be signed: {}",
                        ExceptionUtils.getRootCauseMessage(e));
                }
            }
        }
    }

    private void loadKeys(File jwkSetFile) throws IOException, java.text.ParseException
    {
        this.jwkSet = JWKSet.load(jwkSetFile);

        for (JWK key : this.jwkSet.getKeys()) {
            if (key instanceof RSAKey) {
                this.rsaKey = (RSAKey) key;
            }
        }
    }

    private void generateKeys(File jwkSetFile) throws JOSEException
    {
        this.rsaKey = new RSAKeyGenerator(2048).keyID(RandomStringUtils.randomAlphanumeric(4)).keyUse(KeyUse.SIGNATURE)
            .generate();
        this.jwkSet = new JWKSet(this.rsaKey);

        String json = this.jwkSet.toJSONObject(false).toJSONString();
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
    public JWKSet getJWKSet()
    {
        return this.jwkSet;
    }

    /**
     * @return the issuer
     * @throws MalformedURLException when failing to create the issuer
     */
    public Issuer getIssuer() throws MalformedURLException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        XWikiURLFactory urlFactory = xcontext.getURLFactory();

        return new Issuer(urlFactory.getServerURL(xcontext).toString());
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

        base.append("oidc/");

        return createEndPointURI(base.toString(), endpoint);
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
     * @throws ParseException when failing to create the id token
     * @throws MalformedURLException when failing to get issuer
     * @since 1.3
     */
    public JWT createdIdToken(ClientID clientID, DocumentReference userReference, Nonce nonce, ClaimsRequest claims)
        throws ParseException, MalformedURLException
    {
        Issuer issuer = getIssuer();
        Subject subject = getSubject(userReference);
        List<Audience> audiences =
            clientID != null ? Arrays.asList(new Audience(clientID)) : Collections.<Audience>emptyList();

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime now1year = now.plusYears(1);

        IDTokenClaimsSet idTokenClaimSet =
            new IDTokenClaimsSet(issuer, subject, audiences, now1year.toDate(), now.toDate());

        idTokenClaimSet.setNonce(nonce);

        // Add custom claims
        if (claims != null) {
            for (Entry claim : claims.getIDTokenClaims()) {
                switch (claim.getClaimName()) {
                    case OIDCIdToken.CLAIM_XWIKI_INSTANCE_ID:
                        idTokenClaimSet.setClaim(OIDCIdToken.CLAIM_XWIKI_INSTANCE_ID, this.instance.getInstanceId());
                        break;

                    default:
                        break;
                }
            }
        }

        // Convert to JWT
        if (this.signer != null) {
            SignedJWT signedJWT = new SignedJWT(this.header, idTokenClaimSet.toJWTClaimsSet());

            try {
                signedJWT.sign(this.signer);

                return signedJWT;
            } catch (JOSEException e) {
                this.logger.warn("Failed to sign the id token, returning a plain id token: {}",
                    ExceptionUtils.getRootCauseMessage(e));
            }
        }

        // Fallback on plain JWT in case of problem
        return new PlainJWT(idTokenClaimSet.toJWTClaimsSet());
    }

    /**
     * @param userReference the reference of the user
     * @return the OIDC subject
     */
    public Subject getSubject(DocumentReference userReference)
    {
        return new Subject(this.configuration.getSubMode() == SubFormat.LOCAL ? userReference.getName()
            : this.referenceSerializer.serialize(userReference));
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
}
