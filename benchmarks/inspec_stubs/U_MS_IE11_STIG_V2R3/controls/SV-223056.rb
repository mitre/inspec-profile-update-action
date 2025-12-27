control 'SV-223056' do
  title 'Internet Explorer Development Tools Must Be Disabled.'
  desc 'While the risk associated with browser development tools is more related to the proper design of a web application, a risk vector remains within the browser. The developer tools allow end users and application developers to view and edit all types of web application related data via the browser. Page elements, source code, javascript, API calls, application data, etc. may all be viewed and potentially manipulated. Manipulation could be useful for troubleshooting legitimate issues, and this may be performed in a development environment. Manipulation could also be malicious and must be addressed.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Toolbars >> “Turn off Developer Tools” must be “Enabled”. 
Procedure: Use the Windows Registry Editor to navigate to the following key: HKEY_LOCAL_Machine\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\IEDevTools
Criteria: If the value "Disabled" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Toolbars >> “Turn off Developer Tools” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24729r428718_chk'
  tag severity: 'low'
  tag gid: 'V-223056'
  tag rid: 'SV-223056r428720_rule'
  tag stig_id: 'DTBI1135-IE11'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-24717r428719_fix'
  tag 'documentable'
  tag legacy: ['SV-106631', 'V-97527']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
