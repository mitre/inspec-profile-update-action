control 'SV-79205' do
  title 'Prevent per-user installation of ActiveX controls must be enabled.'
  desc 'This policy setting allows you to prevent the installation of ActiveX controls on a per-user basis. If you enable this policy setting, ActiveX controls cannot be installed on a per-user basis. If you disable or do not configure this policy setting, ActiveX controls can be installed on a per-user basis.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent per-user installation of ActiveX controls” must be ”Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Security\\ActiveX. 

Criteria: If the value "BlockNonAdminActiveXInstall" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent per-user installation of ActiveX controls” to ”Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-65457r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64715'
  tag rid: 'SV-79205r1_rule'
  tag stig_id: 'DTBI1070-IE11'
  tag gtitle: 'DTBI1070-IE11-Per-User ActiveX Controls'
  tag fix_id: 'F-70645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
