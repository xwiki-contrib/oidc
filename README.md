# OpenID Connect

Various tools to manipulate OpenID Connect protocol in XWiki.

* Project Lead: [Thomas Mortagne](http://www.xwiki.org/xwiki/bin/view/XWiki/ThomasMortagne)
* [Documentation & Downloads](http://extensions.xwiki.org/xwiki/bin/view/Extension/OpenID%20Connect/)
* [Issue Tracker](http://jira.xwiki.org/browse/OIDC)
* Communication: [Mailing List](http://dev.xwiki.org/xwiki/bin/view/Community/MailingLists), [IRC](http://dev.xwiki.org/xwiki/bin/view/Community/IRC)
* [Development Practices](http://dev.xwiki.org)
* Minimal XWiki version supported: XWiki 7.4
* License: LGPL 2.1
* Translations: N/A
* Sonar Dashboard: N/A
* Continuous Integration Status: [![Build Status](https://ci.xwiki.org/buildStatus/icon?job=XWiki+Contrib%2Foidc%2Fmaster)](https://ci.xwiki.org/job/XWiki%20Contrib/job/oidc/job/master/)

# Release

* Release

```
mvn release:prepare -Pintegration-tests
mvn release:perform -Pintegration-tests
```

* Update http://extensions.xwiki.org/xwiki/bin/view/Extension/OpenID+Connect/#HReleaseNotes
