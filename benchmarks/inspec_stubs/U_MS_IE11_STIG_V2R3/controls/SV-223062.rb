control 'SV-223062' do
  title 'Accessing data sources across domains must be disallowed (Restricted Sites zone).'
  desc 'The ability to access data zones across domains could cause the user to unknowingly access content hosted on an unauthorized server. This policy setting allows you to manage whether Internet Explorer can access data from another security zone using the Microsoft XML Parser (MSXML) or ActiveX Data Objects (ADO).'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Access data sources across domains' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1406" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Access data sources across domains' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24735r428736_chk'
  tag severity: 'medium'
  tag gid: 'V-223062'
  tag rid: 'SV-223062r428738_rule'
  tag stig_id: 'DTBI122-IE11'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24723r428737_fix'
  tag 'documentable'
  tag legacy: ['SV-59453', 'V-46589']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
