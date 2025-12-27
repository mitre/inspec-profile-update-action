control 'SV-53382' do
  title 'Disabling email forms from the Internet Security Zone must be configured.'
  desc 'InfoPath email forms can be designed by an external attacker and sent over the Internet as part of a phishing attempt. Users might fill out such forms and provide sensitive information to the attacker.
By default, forms that originate from the Internet can be opened, although those forms cannot access content stored in a different domain.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable e-mail forms from the Internet security zone" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value EnableInternetEMailForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable e-mail forms from the Internet security zone" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17656'
  tag rid: 'SV-53382r1_rule'
  tag stig_id: 'DTOO172'
  tag gtitle: 'DTOO172 - EMail forms from Internet Zone'
  tag fix_id: 'F-46306r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
