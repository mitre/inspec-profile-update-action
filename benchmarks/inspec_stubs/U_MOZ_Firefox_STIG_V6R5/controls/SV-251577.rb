control 'SV-251577' do
  title 'Firefox must be configured so that DNS over HTTPS is disabled.'
  desc 'DNS over HTTPS has generally not been adopted in the DoD. DNS is tightly controlled.

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "DNSOverHTTPS" is not displayed under Policy Name or the Policy Value does not have "Enabled" with a value of "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\DNS Over HTTPS
Policy Name: Enabled
Policy State: Disabled

macOS "plist" file:
<key>DNSOverHTTPS</key>
  <dict>
    <key>Enabled</key>
    <false/>

Linux "policies.json" file:
Add the following in the policies section:
"DNSOverHTTPS": {"Enabled": false}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55012r807201_chk'
  tag severity: 'medium'
  tag gid: 'V-251577'
  tag rid: 'SV-251577r879587_rule'
  tag stig_id: 'FFOX-00-000033'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54966r807202_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
