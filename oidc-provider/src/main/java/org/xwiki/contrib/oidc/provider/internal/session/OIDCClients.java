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
package org.xwiki.contrib.oidc.provider.internal.session;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.BackChannelLogoutRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * A helper to access all sessions.
 *
 * @version $Id: c60ed9b2455052c9b46af99f25f8ca47120c6e9e $
 * @since 2.4.0
 */
@Component(roles = OIDCClients.class)
@Singleton
public class OIDCClients
{
    private final Map<ClientID, OIDCClientInformation> clients = new ConcurrentHashMap<>();

    /**
     * @param clientID the client identifier
     * @param clientMetadata the client new metadata to update
     * @return the stored information about the client
     */
    public OIDCClientInformation updateClient(ClientID clientID, OIDCClientMetadata clientMetadata)
    {
        OIDCClientInformation clientInfo = new OIDCClientInformation(clientID, clientMetadata);

        this.clients.put(clientID, clientInfo);

        return clientInfo;
    }

    /**
     * @param clientMetadata the new client metadata
     * @return the stored information about the client
     */
    public OIDCClientInformation addClient(OIDCClientMetadata clientMetadata)
    {
        // Generate a clientId
        ClientID clientID = new ClientID();

        OIDCClientInformation clientInfo = new OIDCClientInformation(clientID, clientMetadata);

        this.clients.put(clientID, clientInfo);

        return clientInfo;
    }

    /**
     * @param clientID the client identifier
     * @return the information registered by the client, or null if no client with this identifier could be found
     */
    public OIDCClientInformation getClient(ClientID clientID)
    {
        return this.clients.get(clientID);
    }

    /**
     * @param clientID the client identifier
     * @return the information registered by the client, or null if no client with this identifier could be found
     */
    public OIDCClientInformation removeClient(ClientID clientID)
    {
        return this.clients.remove(clientID);
    }

    /**
     * @param clientID the id of the client
     * @param logoutToken the token provided by the client to logout the session
     * @throws IOException when failing to execute the logout
     */
    public void logout(ClientID clientID, JWT logoutToken) throws IOException
    {
        OIDCClientInformation clientInformation = this.clients.get(clientID);

        if (clientInformation != null) {
            BackChannelLogoutRequest logoutRequest = new BackChannelLogoutRequest(
                clientInformation.getOIDCMetadata().getBackChannelLogoutURI(), logoutToken);

            HTTPRequest tokenHTTP = logoutRequest.toHTTPRequest();
            tokenHTTP.send();
        }
    }
}
