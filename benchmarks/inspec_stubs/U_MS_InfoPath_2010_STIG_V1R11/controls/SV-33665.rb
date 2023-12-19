control 'SV-33665' do
  title 'Disabling the opening of solutions from the Internet Security Zone must be configured.'
  desc 'Attackers could use InfoPath solutions published to Internet Web sites to try to obtain sensitive information from users. By default, users can open InfoPath solutions that do not contain managed code from sources located in the Internet security zone as defined in the Internet Options dialog box in Internet Explorer.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Disable opening of solutions from the Internet security zone” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value AllowInternetSolutions is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Disable opening of solutions from the Internet security zone” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34126r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17663'
  tag rid: 'SV-33665r1_rule'
  tag stig_id: 'DTOO158 - InfoPath'
  tag gtitle: 'DTOO158 - Solutions from the Internet Zone'
  tag fix_id: 'F-29807r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
