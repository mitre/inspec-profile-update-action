control 'SV-223029' do
  title 'Anti-Malware programs against ActiveX controls must be run for the Intranet zone.'
  desc "This policy setting determines whether Internet Explorer runs Anti-Malware programs against ActiveX controls, to check if they're safe to load on pages.      If you enable this policy setting, Internet Explorer won't check with your Anti-Malware program to see if it's safe to create an instance of the ActiveX control. If you disable this policy setting, Internet Explorer always checks with your Anti-Malware program to see if it's safe to create an instance of the ActiveX control. If you don't configure this policy setting, Internet Explorer won't check with your Anti-Malware program to see if it's safe to create an instance of the ActiveX control. Users can turn this behavior on or off, using Internet Explorer Security settings."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Intranet Zone 'Don't run antimalware programs against ActiveX controls' must be 'Enabled' and 'Disable' selected in the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1  Criteria: If the value "270C" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Intranet Zone 'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24702r428637_chk'
  tag severity: 'medium'
  tag gid: 'V-223029'
  tag rid: 'SV-223029r428639_rule'
  tag stig_id: 'DTBI062-IE11'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24690r428638_fix'
  tag 'documentable'
  tag legacy: ['SV-59865', 'V-46999']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
