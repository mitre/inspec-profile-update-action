control 'SV-251573' do
  title 'The Firefox New Tab page must not show Top Sites, Sponsored Top Sites, Pocket Recommendations, Sponsored Pocket Stories, Searches, Highlights, or Snippets.'
  desc 'The New Tab page by default shows a list of built-in top sites, as well as the top sites the user has visited.

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to advertising software or browser plug-ins that are not related to requirements or provide a wide array of functionality not required for every mission but that cannot be disabled.

The new tab page must not actively show user activity.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "Search" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "TopSites" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "SponsoredTopSites" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "Pocket" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "SponsoredPocket" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "Highlights" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "Snippets" with a value of "false", this is a finding.
If "FirefoxHome" is not displayed under Policy Name or the Policy Value does not have "Locked" with a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Customize Firefox Home
Policy State: Enabled
Policy Value: Uncheck "Search"
Policy Value: Uncheck "Top Sites"
Policy Value: Uncheck "Sponsored Top Sites"
Policy Value: Uncheck "Recommended by Pocket"
Policy Value: Uncheck "Sponsored Pocket Stories"
Policy Value: Uncheck "Download History"
Policy Value: Uncheck "Snippets"
Policy Value: Check "Do not allow settings to be changed"

macOS "plist" file:
Add the following:
<key>FirefoxHome</key>
<dict>
<key>Search</key>
  <false/>
<key>TopSites</key>
  <false/>
<key>SponsoredTopSites</key>
  <false/>
<key>Pocket</key>
  <false/>
<key>SponsoredPocket</key>
  <false/>
<key>Highlights</key>
  <false/>
<key>Snippets</key>
  <false/>
<key>Locked</key>
  <true/>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"FirefoxHome": {
  "Search": false,
  "TopSites": false,
  "SponsoredTopSites": false,
  "Pocket": false,
  "SponsoredPocket": false,
  "Highlights": false,
  "Snippets": false,
  "locked": true
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55008r822779_chk'
  tag severity: 'medium'
  tag gid: 'V-251573'
  tag rid: 'SV-251573r879587_rule'
  tag stig_id: 'FFOX-00-000029'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54962r822780_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
