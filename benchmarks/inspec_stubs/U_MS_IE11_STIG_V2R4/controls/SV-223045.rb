control 'SV-223045' do
  title 'The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone).'
  desc 'ActiveX controls that are not marked safe for scripting should not be executed. Although this is not a complete security measure for a control to be marked safe for scripting, if a control is not marked safe, it should not be initialized and executed. This setting causes both unsafe and safe controls to be initialized and scripted, ignoring the Script ActiveX controls marked safe for scripting option. This increases the risk of malicious code being loaded and executed by the browser. If you enable this policy setting, ActiveX controls are run, loaded with parameters and scripted without setting object safety for untrusted data or scripts. If you disable this policy setting, ActiveX controls that cannot be made safe are not loaded with parameters or scripted. This setting is not recommended, except for secure and administered zones.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone >> ”Initialize and script ActiveX controls not marked as safe” must be ”Enabled” and ”Disable” selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1. 

Criteria: If the value "1201" is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone >> ”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24718r428685_chk'
  tag severity: 'medium'
  tag gid: 'V-223045'
  tag rid: 'SV-223045r879630_rule'
  tag stig_id: 'DTBI1090-IE11'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24706r428686_fix'
  tag 'documentable'
  tag legacy: ['SV-79213', 'V-64723']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
