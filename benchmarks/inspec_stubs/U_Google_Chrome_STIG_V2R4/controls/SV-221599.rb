control 'SV-221599' do
  title 'Chrome development tools must be disabled.'
  desc 'While the risk associated with browser development tools is more related to the proper design of a web application, a risk vector remains within the browser. The developer tools allow end users and application developers to view and edit all types of web application related data via the browser. Page elements, source code, javascript, API calls, application data, etc. may all be viewed and potentially manipulated. Manipulation could be useful for troubleshooting legitimate issues, and this may be performed in a development environment. Manipulation could also be malicious and must be addressed.'
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy 
2. If the policy "DeveloperToolsAvailability" is not shown or is not set to "2", this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the key "DeveloperToolsAvailability" does not exist or is not set to "2", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the "group policy editor" tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome
Policy Name: Control where Developer Tools can be used
Policy State: Enabled
Policy Value: Disallow usage of the Developer Tools'
  impact 0.3
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23314r478214_chk'
  tag severity: 'low'
  tag gid: 'V-221599'
  tag rid: 'SV-221599r615937_rule'
  tag stig_id: 'DTBC-0068'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-23303r478215_fix'
  tag 'documentable'
  tag legacy: ['SV-106629', 'V-97525']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
