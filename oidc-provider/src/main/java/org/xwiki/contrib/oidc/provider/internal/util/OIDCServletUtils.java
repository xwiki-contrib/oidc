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

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;

/**
 * Provider various Servlet related tools.
 * 
 * @version $Id$
 */
public final class OIDCServletUtils
{
    /**
     * Prevents public instantiation.
     */
    private OIDCServletUtils()
    {
    }

    // TODO: remove when
    // https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/184/servletutils-createhttprequest-loose
    // is fixed
    public static HTTPRequest createHTTPRequest(final HttpServletRequest sr) throws IOException
    {
        HTTPRequest request = ServletUtils.createHTTPRequest(sr);

        // Workaround bug
        if (request.getContentType() != null
            && request.getContentType().getBaseType().equals(CommonContentTypes.APPLICATION_URLENCODED.getBaseType())
            && StringUtils.isEmpty(request.getQuery())) {
            StringBuilder newContent = new StringBuilder();
            for (Map.Entry<String, String[]> entry : sr.getParameterMap().entrySet()) {
                if (newContent.length() > 0) {
                    newContent.append('&');
                }
                newContent.append(URLEncoder.encode(entry.getKey(), "UTF8"));
                newContent.append('=');
                newContent.append(URLEncoder.encode(entry.getValue()[0], "UTF8"));
            }
            request.setQuery(newContent.toString());
        }

        return request;
    }
}
