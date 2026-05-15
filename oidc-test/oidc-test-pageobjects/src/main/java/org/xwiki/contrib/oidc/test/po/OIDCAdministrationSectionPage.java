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
package org.xwiki.contrib.oidc.test.po;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.xwiki.administration.test.po.AdministrationSectionPage;

/**
 * Represents the actions possible on the OpenID connect Administration at wiki level.
 *
 * @version $Id: a9d09c8b6af7f1411760636950fa485cc241efd1 $
 */
public class OIDCAdministrationSectionPage extends AdministrationSectionPage
{
    @FindBy(id = "client_mode_dynamic")
    private WebElement dynamicModeRadio;

    @FindBy(id = "client_mode_static")
    private WebElement staticModeRadio;

    @FindBy(id = "client_mode_save")
    private WebElement saveButton;

    public OIDCAdministrationSectionPage()
    {
        super("OpenID Connect");

        waitUntilActionButtonIsLoaded();
    }

    public static OIDCAdministrationSectionPage gotoPage()
    {
        getUtil().gotoPage("XWiki", "XWikiPreferences", "admin", "section=OpenID%20Connect");

        return new OIDCAdministrationSectionPage();
    }

    public void setDynamicMode()
    {
        this.dynamicModeRadio.click();
    }

    public void setStaticMode()
    {
        this.staticModeRadio.click();
    }

    public OIDCAdministrationSectionPage clickSaveButton()
    {
        this.saveButton.click();

        return new OIDCAdministrationSectionPage();
    }
}
