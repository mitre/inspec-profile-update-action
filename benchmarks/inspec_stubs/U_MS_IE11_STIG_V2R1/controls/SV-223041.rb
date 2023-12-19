control 'SV-223041' do
  title 'Prevent per-user installation of ActiveX controls must be enabled.'
  desc 'This policy setting allows you to prevent the installation of ActiveX controls on a per-user basis. If you enable this policy setting, ActiveX controls cannot be installed on a per-user basis. If you disable or do not configure this policy setting, ActiveX controls can be installed on a per-user basis.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent per-user installation of ActiveX controls” must be ”Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Security\\ActiveX. 

Criteria: If the value "BlockNonAdminActiveXInstall" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent per-user installation of ActiveX controls” to ”Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24714r428673_chk'
  tag severity: 'medium'
  tag gid: 'V-223041'
  tag rid: 'SV-223041r428675_rule'
  tag stig_id: 'DTBI1070-IE11'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24702r428674_fix'
  tag 'documentable'
  tag legacy: ['SV-79205', 'V-64715']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
