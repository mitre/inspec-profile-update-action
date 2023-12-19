control 'SV-40567' do
  title 'Accessing data sources across domains must be disallowed (Internet zone).'
  desc 'The ability to access data zones across domains could cause the user to unknowingly access content hosted on an unauthorized server. Access to data sources across multiple domains must be controlled based upon the site being browsed. This policy setting allows you to manage whether Internet Explorer can access data from another security zone using the Microsoft XML Parser (MSXML) or ActiveX Data Objects (ADO).'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Access data sources across domains" must be "Enabled" and "Disable" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1406 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Access data sources across domains" to "Enabled" and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39330r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6250'
  tag rid: 'SV-40567r1_rule'
  tag stig_id: 'DTBI032'
  tag gtitle: 'DTBI032 - Data sources across domains - Internet'
  tag fix_id: 'F-34437r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCMC-1'
end
