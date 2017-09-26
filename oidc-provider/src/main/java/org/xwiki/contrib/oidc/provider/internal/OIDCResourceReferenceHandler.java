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

import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.container.servlet.ServletResponse;
import org.xwiki.context.Execution;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.resource.AbstractResourceReferenceHandler;
import org.xwiki.resource.ResourceReference;
import org.xwiki.resource.ResourceReferenceHandlerChain;
import org.xwiki.resource.ResourceReferenceHandlerException;
import org.xwiki.resource.ResourceType;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiServletContext;
import com.xpn.xwiki.web.XWikiServletRequest;
import com.xpn.xwiki.web.XWikiServletResponse;

/**
 * OpenID Connect entry point.
 *
 * @version $Id: 2e98f0b413b4ae324afc083bad5ff79cc810d83e $
 */
@Component
@Named("oidc")
@Singleton
public class OIDCResourceReferenceHandler extends AbstractResourceReferenceHandler<ResourceType>
{
    @Inject
    private Container container;

    @Inject
    private ComponentManager componentManager;

    @Inject
    private OIDCEndpoint unknown;

    @Inject
    private Execution execution;

    @Inject
    private Logger logger;

    @Override
    public List<ResourceType> getSupportedResourceReferences()
    {
        return Arrays.asList(OIDCResourceReference.TYPE);
    }

    @Override
    public void handle(ResourceReference resourceReference, ResourceReferenceHandlerChain chain)
        throws ResourceReferenceHandlerException
    {
        OIDCResourceReference reference = (OIDCResourceReference) resourceReference;

        Request request = this.container.getRequest();

        if (!(request instanceof ServletRequest)) {
            throw new ResourceReferenceHandlerException("Unsupported request type [" + request.getClass() + "]");
        }

        HttpServletRequest httpServletRequest = ((ServletRequest) request).getHttpServletRequest();
        HttpServletResponse httpServletReponse =
            ((ServletResponse) this.container.getResponse()).getHttpServletResponse();

        initializeXWikiContext(httpServletRequest, httpServletReponse);

        try {
            handle(reference, httpServletRequest, httpServletReponse);
        } catch (Exception e) {
            throw new ResourceReferenceHandlerException("Failed to handle http servlet request", e);
        }

        // Be a good citizen, continue the chain, in case some lower-priority Handler has something to do for this
        // Resource Reference.
        chain.handleNext(reference);
    }

    private void handle(OIDCResourceReference reference, HttpServletRequest httpServletRequest,
        HttpServletResponse servletResponse) throws Exception
    {
        // Convert from Servlet http request to generic http request
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(httpServletRequest);

        this.logger.debug("OIDC: Reference: [{}]", reference);

        Response response;
        if (this.componentManager.hasComponent(OIDCEndpoint.class, reference.getEndpoint())) {
            OIDCEndpoint endpoint = this.componentManager.getInstance(OIDCEndpoint.class, reference.getEndpoint());

            response = endpoint.handle(httpRequest, reference);
        } else if (this.componentManager.hasComponent(OIDCEndpoint.class, reference.getPath())) {
            OIDCEndpoint endpoint = this.componentManager.getInstance(OIDCEndpoint.class, reference.getPath());

            response = endpoint.handle(httpRequest, reference);
        } else {
            response = this.unknown.handle(httpRequest, reference);
        }

        // response might be null if the handled already answered the client (for example a redirect to the login
        // screen)
        if (response != null) {
            // Create http response
            HTTPResponse httpResponse = response.toHTTPResponse();

            // Apply generic http response to Sevlet http response
            ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
        }
    }

    protected void initializeXWikiContext(HttpServletRequest request, HttpServletResponse response)
        throws ResourceReferenceHandlerException
    {
        try {
            XWikiServletContext xwikiEngine = new XWikiServletContext(request.getServletContext());
            XWikiServletRequest xwikiRequest = new XWikiServletRequest(request);
            XWikiServletResponse xwikiResponse = new XWikiServletResponse(response);

            // Create the XWiki context.
            XWikiContext context = Utils.prepareContext("", xwikiRequest, xwikiResponse, xwikiEngine);

            // Initialize the XWiki database. XWiki#getXWiki(XWikiContext) calls XWikiContext.setWiki(XWiki).
            XWiki xwiki = XWiki.getXWiki(context);

            // Initialize the URL factory.
            context.setURLFactory(xwiki.getURLFactoryService().createURLFactory(context.getMode(), context));

            // Prepare the localized resources, according to the selected language.
            xwiki.prepareResources(context);

            // Put the XWikiContext in the ExecutionContext
            context.declareInExecutionContext(this.execution.getContext());
        } catch (XWikiException e) {
            throw new ResourceReferenceHandlerException("Failed to initialize the XWiki context.", e);
        }
    }
}
