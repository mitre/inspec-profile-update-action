control 'SV-235751' do
  title 'Edge development tools must be disabled.'
  desc 'While the risk associated with browser development tools is more related to the proper design of a web application, a risk vector remains within the browser. The developer tools allow end users and application developers to view and edit all types of web application-related data via the browser. Page elements, source code, javascript, API calls, application data, etc., may all be viewed and potentially manipulated. Manipulation could be useful for troubleshooting legitimate issues, and this may be performed in a development environment. Manipulation could also be malicious and must be addressed.'
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Control where developer tools can be used" with the option value set to "Don't allow using the developer tools".

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge

If the value for "DeveloperToolsAvailability" is not set to "REG_DWORD = 2", this is a finding.)
  desc 'fix', %q(Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Control where developer tools can be used" to "enabled" and select "Don't allow using the developer tools".)
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38970r626449_chk'
  tag severity: 'low'
  tag gid: 'V-235751'
  tag rid: 'SV-235751r626523_rule'
  tag stig_id: 'EDGE-00-000034'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38933r626450_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
