control 'SV-34111' do
  title 'InfoPath must be enforced to not use e-mail forms from the Intranet security zone.'
  desc 'InfoPath e-mail forms can be designed by an internal attacker and sent over the local intranet, and users might fill out such forms and provide sensitive information to the attacker.  By default, forms that originate from the local intranet can be opened.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable e-mail forms from the Intranet security zone” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value EnableIntranetEMailForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable e-mail forms from the Intranet security zone” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34214r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26618'
  tag rid: 'SV-34111r1_rule'
  tag stig_id: 'DTOO294 - InfoPath'
  tag gtitle: 'DTOO294 - E-mail forms from the Intranet'
  tag fix_id: 'F-29905r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
