control 'SV-251569' do
  title 'Firefox Enhanced Tracking Protection must be enabled.'
  desc 'Tracking generally refers to content, cookies, or scripts that can collect browsing data across multiple sites.

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to advertising software or browser plug-ins that are not related to requirements or provide a wide array of functionality not required for every mission but that cannot be disabled.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "browser.contentblocking.category" is not displayed with a value of "strict", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Preferences
Policy State: Enabled
Policy Value:
{
  "browser.contentblocking.category": {
    "Value": "strict",
    "Status": "locked"
  }
}

macOS "plist" file:
Add the following:
<key>Preferences</key>
<dict>
  <key>browser.contentblocking.category</key>
  <dict>
    <key>Value</key>
    <string>strict</string>
    <key>Status</key>
    <string>locked</string>
  </dict>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"Preferences": {
  "browser.contentblocking.category": {
    "Value": "strict",
    "Status": "locked"
  }
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55004r807177_chk'
  tag severity: 'medium'
  tag gid: 'V-251569'
  tag rid: 'SV-251569r879587_rule'
  tag stig_id: 'FFOX-00-000025'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54958r807178_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
