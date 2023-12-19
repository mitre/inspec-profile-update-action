control 'SV-59373' do
  title 'Accessing data sources across domains must be disallowed (Internet zone).'
  desc 'The ability to access data zones across domains could cause the user to unknowingly access content hosted on an unauthorized server. Access to data sources across multiple domains must be controlled based upon the site being browsed. This policy setting allows you to manage whether Internet Explorer can access data from another security zone using the Microsoft XML Parser (MSXML) or ActiveX Data Objects (ADO).'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Access data sources across domains' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1406" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Access data sources across domains' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49699r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46509'
  tag rid: 'SV-59373r1_rule'
  tag stig_id: 'DTBI032-IE11'
  tag gtitle: 'DTBI032-IE11-Access data sources across domains - Internet'
  tag fix_id: 'F-50299r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
