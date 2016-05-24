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
package org.xwiki.contrib.oidc.provider.internal.util;

import javax.mail.internet.ContentType;
import javax.mail.internet.ParameterList;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

/**
 * Implementation of {@link Response} which return a simple content.
 * 
 * @version $Id$
 */
public class ContentResponse implements Response
{
    /**
     * The primary type for text content types.
     */
    public static final String PRIMARYTYPE_TEXT = "text";

    /**
     * Mime type for HTML.
     */
    public static final ContentType CONTENTTYPE_HTML = new ContentType(PRIMARYTYPE_TEXT, "html", new ParameterList());

    /**
     * Mime type for plain text.
     */
    public static final ContentType CONTENTTYPE_PLAIN = new ContentType(PRIMARYTYPE_TEXT, "plain", new ParameterList());

    private final HTTPResponse httpResponse;

    /**
     * @param type the type of the content
     * @param content the content to return
     * @param statusCode the status code to return
     */
    public ContentResponse(ContentType type, String content, int statusCode)
    {
        this.httpResponse = new HTTPResponse(statusCode);

        this.httpResponse.setContentType(type);
        this.httpResponse.setContent(content);
    }

    @Override
    public HTTPResponse toHTTPResponse()
    {
        return this.httpResponse;
    }

    @Override
    public boolean indicatesSuccess()
    {
        return true;
    }
}
