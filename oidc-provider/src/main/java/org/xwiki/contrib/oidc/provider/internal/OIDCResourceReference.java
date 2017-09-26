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

import java.util.List;

import org.xwiki.model.reference.WikiReference;
import org.xwiki.resource.ResourceType;
import org.xwiki.resource.entity.EntityResourceAction;
import org.xwiki.resource.entity.EntityResourceReference;

/**
 * Dummy type for OpenID Connect entry point.
 *
 * @version $Id: 97638fe25bc709cd9296ea452b5d13077aab014b $
 */
public class OIDCResourceReference extends EntityResourceReference
{
    /**
     * Represents a WebJars Resource Type.
     */
    public static final ResourceType TYPE = new ResourceType("oidc");

    private String path;

    private String endpoint;

    private List<String> pathSegments;

    /**
     * Default constructor.
     * 
     * @param path the path starting with the endpoint
     * @param endpoint the target endpoint
     * @param pathSegments the rest of the path
     * @param wiki the wiki being requested
     */
    public OIDCResourceReference(String path, String endpoint, List<String> pathSegments, WikiReference wiki)
    {
        super(wiki, EntityResourceAction.fromString(""));

        setType(TYPE);

        this.path = path;
        this.endpoint = endpoint;
        this.pathSegments = pathSegments;
    }

    /**
     * @return the path starting with the endpoint
     */
    public String getPath()
    {
        return this.path;
    }

    /**
     * @return the endpoint
     */
    public String getEndpoint()
    {
        return this.endpoint;
    }

    /**
     * @return the endpoint path (elements after the endpoint)
     */
    public List<String> getPathSegments()
    {
        return this.pathSegments;
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();

        builder.append("path = ");
        builder.append(getPath());
        builder.append(", endpoint = ");
        builder.append(getEndpoint());
        builder.append(", pathSegments = ");
        builder.append(getPathSegments());

        return super.toString();
    }
}
