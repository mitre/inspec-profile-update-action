control 'SV-53385' do
  title 'InfoPath must be enforced to not use email forms from the Intranet security zone.'
  desc 'InfoPath email forms can be designed by an internal attacker and sent over the local intranet, and users might fill out such forms and provide sensitive information to the attacker. By default, forms that originate from the local intranet can be opened.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable e-mail forms from the Intranet security zone" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value EnableIntranetEMailForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable e-mail forms from the Intranet security zone" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47630r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26618'
  tag rid: 'SV-53385r1_rule'
  tag stig_id: 'DTOO294'
  tag gtitle: 'DTOO294 - E-mail forms from the Intranet'
  tag fix_id: 'F-46309r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
