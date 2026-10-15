# OAuth2 and OpenID Connect

Various tools to manipulate OAuth2 and OpenID Connect protocols in XWiki: make XWiki an OpenID Connect provider, authenticate XWiki users with an external OpenID Connect provider, etc.

* Project Lead: [Thomas Mortagne](https://www.xwiki.org/xwiki/bin/view/XWiki/ThomasMortagne)
* Documentation & Downloads: [Documentation & Download](https://extensions.xwiki.org/xwiki/bin/view/Extension/OpenID%20Connect/)
* [Issue Tracker](https://jira.xwiki.org/browse/OIDC)
* Communication: [Forum](https://forum.xwiki.org/), [Chat](https://dev.xwiki.org/xwiki/bin/view/Community/Chat)
* [Development Practices](https://dev.xwiki.org)
* Minimal XWiki version supported: XWiki 14.10.2
* License: LGPL 2.1
* Translations: [OpenID Connect Provider](https://l10n.xwiki.org/projects/xwiki-contrib/oidc-provider/), [OpenID Connect Authenticator](https://l10n.xwiki.org/projects/xwiki-contrib/oidc-authenticator/), [OpenID Connect Token Authenticator](https://l10n.xwiki.org/projects/xwiki-contrib/openid-connect-token-authenticator/), [OpenID Connect Consent](https://l10n.xwiki.org/projects/xwiki-contrib/openid-connect-consent/)
* Sonar Dashboard: N/A
* Continuous Integration Status: [![Build Status](https://ci.xwiki.org/job/XWiki%20Contrib/job/oidc/job/master/badge/icon)](https://ci.xwiki.org/job/XWiki%20Contrib/job/oidc/job/master/)

# Release

* Release

```
mvn release:prepare -Pintegration-tests
mvn release:perform -Pintegration-tests
```

* Update https://extensions.xwiki.org/xwiki/bin/view/Extension/OpenID%20Connect/#HVersions
