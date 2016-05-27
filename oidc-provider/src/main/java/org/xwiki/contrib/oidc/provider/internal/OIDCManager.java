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

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.joda.time.LocalDateTime;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.util.ContentResponse;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.template.Template;
import org.xwiki.template.TemplateManager;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.internal.template.SUExecutor;
import com.xpn.xwiki.user.api.XWikiRightService;
import com.xpn.xwiki.web.XWikiURLFactory;

/**
 * Main utility for OIDC provider.
 * 
 * @version $Id$
 */
@Component(roles = OIDCManager.class)
@Singleton
public class OIDCManager
{
    private static final DocumentReference SUPERADMIN_REFERENCE =
        new DocumentReference("xwiki", XWiki.SYSTEM_SPACE, XWikiRightService.SUPERADMIN_USER);

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private EntityReferenceSerializer<String> referenceSerializer;

    @Inject
    private TemplateManager templates;

    @Inject
    private SUExecutor suExecutor;

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

        base.append('/');

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
     * @return the id token
     * @throws ParseException when failing to create the id token
     * @throws MalformedURLException when failing to get issuer
     */
    public JWT createdIdToken(ClientID clientID, DocumentReference userReference, Nonce nonce)
        throws ParseException, MalformedURLException
    {
        Issuer issuer = getIssuer();
        Subject subject = getSubject(userReference);
        List<Audience> audiences = Arrays.asList(new Audience(clientID));

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime now1year = now.plusYears(1);

        IDTokenClaimsSet idTokenClaimSet =
            new IDTokenClaimsSet(issuer, subject, audiences, now1year.toDate(), now.toDate());

        idTokenClaimSet.setNonce(nonce);

        // Convert to JWT
        return new PlainJWT(idTokenClaimSet.toJWTClaimsSet());
    }

    /**
     * @param userReference the reference of the user
     * @return the OIDC subject
     */
    public Subject getSubject(DocumentReference userReference)
    {
        return new Subject(this.referenceSerializer.serialize(userReference));
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
        // Search overwritten template
        Template template = this.templates.getTemplate(templateName);

        if (template != null) {
            return executeTemplate(template);
        }

        // Search default template
        try (InputStream stream = getClass().getResourceAsStream('/' + templateName)) {
            if (stream == null) {
                throw new OIDCException("Failed to find template [" + templateName + "]");
            }

            return evaluateContent(IOUtils.toString(stream));
        }
    }

    /**
     * Run a template and generate a HTML content response.
     * 
     * @param templateName the name of the template
     * @param request the input request
     * @return the HTML content response
     * @throws Exception when failing to execute the template
     */
    public Response executeTemplate(String templateName, AuthenticationRequest request) throws Exception
    {
        return executeTemplate(templateName);
    }

    public void executeTemplate(String templateName, HttpServletResponse servletResponse) throws Exception
    {
        Response response = executeTemplate(templateName);

        ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
    }

    private Response executeTemplate(Template template) throws Exception
    {
        return evaluateContent(template.getContent().getContent());
    }

    private Response evaluateContent(final String content) throws Exception
    {
        String html = this.suExecutor.call(new Callable<String>()
        {
            @Override
            public String call() throws Exception
            {
                return xcontextProvider.get().getWiki().evaluateVelocity(content, "oidc");
            }
        }, SUPERADMIN_REFERENCE);

        return new ContentResponse(ContentResponse.CONTENTTYPE_HTML, html, HTTPResponse.SC_OK);
    }
}
