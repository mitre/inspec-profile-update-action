control 'SV-53379' do
  title 'InfoPath 2003 forms as email forms in InfoPath 2013 must be disallowed.'
  desc "An attacker might target InfoPath 2003 forms to try and compromise an organization's security. InfoPath 2003 did not write a published location for email forms, which means forms could open without a corresponding published location.
By default, InfoPath sends all forms via email using InfoPath email forms integration, including forms created using the InfoPath 2003 file format."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable sending InfoPath 2003 Forms as e-mail forms" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath

Criteria: If the value DisableInfoPath2003EmailForms is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable sending InfoPath 2003 Forms as e-mail forms" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17668'
  tag rid: 'SV-53379r1_rule'
  tag stig_id: 'DTOO170'
  tag gtitle: 'DTOO170 - 2003 forms as email'
  tag fix_id: 'F-46303r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
