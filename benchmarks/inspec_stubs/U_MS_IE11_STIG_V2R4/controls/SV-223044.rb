control 'SV-223044' do
  title 'Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled.'
  desc 'This policy setting controls whether SmartScreen Filter scans pages in this zone for malicious content. If you enable this policy setting, SmartScreen Filter scans pages in this zone for malicious content. If you disable this policy setting, SmartScreen Filter does not scan pages in this zone for malicious content. If you do not configure this policy setting, the user can choose whether SmartScreen Filter scans pages in this zone for malicious content.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone >> ”Turn on SmartScreen Filter scan” must be ”Enabled” and ”Enable” selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4. 

Criteria: If the value "2301" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone >> ”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24717r428682_chk'
  tag severity: 'medium'
  tag gid: 'V-223044'
  tag rid: 'SV-223044r879664_rule'
  tag stig_id: 'DTBI1085-IE11'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-24705r428683_fix'
  tag 'documentable'
  tag legacy: ['SV-79211', 'V-64721']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
