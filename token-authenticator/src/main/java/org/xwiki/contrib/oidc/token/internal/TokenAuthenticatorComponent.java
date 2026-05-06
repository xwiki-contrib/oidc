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
package org.xwiki.contrib.oidc.token.internal;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.token.TokenAuthService;
import org.xwiki.security.authservice.AbstractXWikiAuthServiceWrapper;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

/**
 * Expose the OpenID Connect Provider bridge authenticator as component.
 * <p>
 * This class has been introduced in 2.21.0 but the component role hint/type it's covering has been introduced in
 * 1.35.0.
 * 
 * @version $Id$
 * @since 1.35.0
 */
@Component
@Singleton
@Named(TokenAuthenticatorComponent.ID)
public class TokenAuthenticatorComponent extends AbstractXWikiAuthServiceWrapper implements XWikiAuthServiceComponent
{
    /**
     * The identifier of the authenticator.
     */
    public static final String ID = "oidc-provider-bridge";

    /**
     * Wrap a {@link TokenAuthService} instance.
     */
    public TokenAuthenticatorComponent()
    {
        super(new TokenAuthService());
    }

    @Override
    public String getId()
    {
        return ID;
    }
}
