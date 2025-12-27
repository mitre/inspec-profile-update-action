control 'SV-34119' do
  title 'InfoPath e-mail forms in Outlook must be disallowed.'
  desc 'Attackers can send users InfoPath e-mail forms in an attempt to gain access to confidential information.  Depending on the level of trust of the forms, it might also be possible to gain access to other data automatically.  By default, Outlook 2010 uses the InfoPath e-mail forms feature to render forms in Outlook and allows users to fill them out in place.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable InfoPath e-mail forms in Outlook” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value DisableInfopathForms is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable InfoPath e-mail forms in Outlook” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34215r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26619'
  tag rid: 'SV-34119r1_rule'
  tag stig_id: 'DTOO295 - InfoPath'
  tag gtitle: 'DTOO295 - InfoPath e-mail forms in Outlook'
  tag fix_id: 'F-29906r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
