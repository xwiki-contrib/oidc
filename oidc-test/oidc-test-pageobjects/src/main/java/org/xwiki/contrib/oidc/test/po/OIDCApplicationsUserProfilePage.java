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

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.xwiki.user.test.po.AbstractUserProfilePage;

/**
 * The user profile page used to manipulate OIDC tokens.
 * 
 * @version $Id$
 * @since 2.13.0
 */
public class OIDCApplicationsUserProfilePage extends AbstractUserProfilePage
{
    @FindBy(id = "input_application_name")
    private WebElement applicationNameInput;

    @FindBy(name = "oidc_consent_create")
    private WebElement createConsentButton;

    public static OIDCApplicationsUserProfilePage gotoPage(String username)
    {
        getUtil().gotoPage("XWiki", username, "view", "category=userapplications");

        return new OIDCApplicationsUserProfilePage(username);
    }

    /**
     * @since 2.18.2
     */
    public static boolean isAllowed()
    {
        return getUtil().getDriver().hasElementWithoutWaiting(By.id("input_application_name"));
    }

    public OIDCApplicationsUserProfilePage(String username)
    {
        super(username);
        getDriver().waitUntilElementIsVisible(By.id("userapplicationsPane"));
    }

    public void setApplicationName(String applicationName)
    {
        this.applicationNameInput.clear();
        this.applicationNameInput.sendKeys(applicationName);
    }

    public OIDCApplicationsUserProfilePage clickCreate()
    {
        this.createConsentButton.click();

        return new OIDCApplicationsUserProfilePage(getUsername());
    }

    public String getToken()
    {
        WebElement div = getDriver().findElementWithoutWaiting(By.xpath("//div[starts-with(text(),'Bearer ')]"));
        return div.getText().substring("Bearer ".length());
    }
}
