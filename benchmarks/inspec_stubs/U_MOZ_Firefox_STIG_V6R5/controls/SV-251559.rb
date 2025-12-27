control 'SV-251559' do
  title 'Firefox development tools must be disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web browser includes any information about the web browser and plug-ins or modules being used. When debugging or trace information is enabled in a production web browser, information about the web browser, such as web browser type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any back ends being used for data storage may be displayed. Because this information may be placed in logs and general messages during normal operation of the web browser, an attacker does not have to cause an error condition to gain this information.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "DisableDeveloperTools" is not displayed under Policy Name or the Policy Value is not "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Developer Tools
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>DisableDeveloperTools</key>
<true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisableDeveloperTools": true'
  impact 0.3
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54994r807147_chk'
  tag severity: 'low'
  tag gid: 'V-251559'
  tag rid: 'SV-251559r879655_rule'
  tag stig_id: 'FFOX-00-000015'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-54948r807148_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
