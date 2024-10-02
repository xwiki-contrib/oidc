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
package org.xwiki.contrib.oidc.provider.script;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.script.SafeOIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.contrib.oidc.script.OIDCScriptService;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.user.UserReference;

import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * Various script APIs related to the OpenID Connect provider.
 *
 * @version $Id: f4857b3769a358bf836e0b6058bafdd0913d7c2c $
 * @since 2.13.0
 */
@Component
@Named(OIDCScriptService.ROLEHINT + '.' + OIDCProviderScriptService.ID)
@Singleton
public class OIDCProviderScriptService implements ScriptService
{
    /**
     * The identifier of the sub extension {@link org.xwiki.script.service.ScriptService}.
     */
    public static final String ID = "provider";

    @Inject
    private OIDCStore store;

    @Inject
    private ContextualAuthorizationManager authorization;

    /**
     * @param userReference the reference of the user to whom the consent are associated
     * @return the consents
     * @throws OIDCException when failing to load the consents
     */
    public List<OIDCConsent> getConsents(UserReference userReference) throws OIDCException
    {
        return this.store.getConsents(userReference).stream().map(SafeOIDCConsent::new).collect(Collectors.toList());
    }

    /**
     * @param userReference the user to whom the consent is associated
     * @param clientID the OIDC client ID
     * @param lifetime the time after which the consent will be expired
     * @return the created consent
     * @throws OIDCException when failing to add a consent
     * @throws AccessDeniedException when the author if the calling script is not allowed to create a consent
     */
    public OIDCConsent addConsent(UserReference userReference, String clientID, long lifetime)
        throws OIDCException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        return this.store.createAndSaveConsent(userReference, new ClientID(clientID),
            Date.from(Instant.now().plusSeconds(lifetime)));
    }

    /**
     * @param userReference the user to whom the consent is associated
     * @param clientID the OIDC client ID
     * @param expirationDate the date after which the consent will be expired
     * @return the created consent
     * @throws OIDCException when failing to add a consent
     * @throws AccessDeniedException when the author if the calling script is not allowed to create a consent
     */
    public OIDCConsent addConsent(UserReference userReference, String clientID, Date expirationDate)
        throws OIDCException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        return this.store.createAndSaveConsent(userReference, new ClientID(clientID), expirationDate);
    }

    /**
     * @param id the identifier of the consent
     * @throws OIDCException when failing to delete the consent
     * @throws AccessDeniedException when the author if the calling script is not allowed to create a consent
     */
    public void deleteConsent(String id) throws OIDCException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        this.store.deleteConsent(id);
    }
}
