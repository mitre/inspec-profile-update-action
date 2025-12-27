control 'SV-53381' do
  title 'Disabling email forms running in Restricted Security Level must be configured.'
  desc 'InfoPath forms running with the restricted security level, can only access data stored on the forms. However, a malicious user could still send an email form running with the restricted security level, in an attempt to access sensitive information provided by users.
By default InfoPath email forms running with the restricted security level can be opened.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable e-mail forms running in restricted security level" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value EnableRestrictedEMailForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable e-mail forms running in restricted security level" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47626r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17657'
  tag rid: 'SV-53381r1_rule'
  tag stig_id: 'DTOO171'
  tag gtitle: 'DTOO171 - EMail forms in Restricted Security'
  tag fix_id: 'F-46305r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
