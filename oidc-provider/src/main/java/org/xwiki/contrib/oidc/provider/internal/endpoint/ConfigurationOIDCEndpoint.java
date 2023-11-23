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
package org.xwiki.contrib.oidc.provider.internal.endpoint;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.util.ContentResponse;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * Return provider configuration (mostly various endpoints URLs).
 * 
 * @version $Id$
 */
@Component(hints = {"", ".well-known/openid-configuration"})
@Singleton
public class ConfigurationOIDCEndpoint implements OIDCEndpoint
{
    @Inject
    private OIDCManager manager;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        Issuer issuer = this.manager.getIssuer();
        List<SubjectType> subjectTypes = Arrays.asList(SubjectType.PUBLIC);
        URI jwkSetURI = this.manager.createEndPointURI(JWKOIDCEndpoint.HINT);

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetURI);

        metadata.setScopes(new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL,
            OIDCScopeValue.ADDRESS, OIDCScopeValue.PHONE));
        metadata.setResponseTypes(List.of(ResponseType.CODE));

        metadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));

        metadata.setAuthorizationEndpointURI(this.manager.createEndPointURI(AuthorizationOIDCEndpoint.HINT));
        metadata.setTokenEndpointURI(this.manager.createEndPointURI(TokenOIDCEndpoint.HINT));
        metadata.setUserInfoEndpointURI(this.manager.createEndPointURI(UserInfoOIDCEndpoint.HINT));
        metadata.setRegistrationEndpointURI(this.manager.createEndPointURI(RegisterAddOIDCEndpoint.HINT));
        metadata.setEndSessionEndpointURI(this.manager.createEndPointURI(LogoutOIDCEndpoint.HINT));
        metadata.setSupportsBackChannelLogout(true);

        return new ContentResponse(ContentType.APPLICATION_JSON, metadata.toJSONObject().toString(),
            HTTPResponse.SC_OK);
    }
}
