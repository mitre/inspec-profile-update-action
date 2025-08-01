control 'SV-53934' do
  title 'Outlook Security Mode must be configured to use Group Policy settings.'
  desc 'If users can configure security themselves, they might choose levels of security that leave their computers vulnerable to attack. By default, Outlook users can configure security for themselves, and Outlook ignores any security-related settings that are configured in Group Policy.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Security Form Settings "Outlook Security Mode" is "Enabled (Use Outlook Security Group Policy)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value AdminSecurityMode is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Security Form Settings "Outlook Security Mode" to "Enabled (Use Outlook Security Group Policy)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47944r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17760'
  tag rid: 'SV-53934r2_rule'
  tag stig_id: 'DTOO239'
  tag gtitle: 'DTOO239 - Outlook Security Mode'
  tag fix_id: 'F-46834r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
