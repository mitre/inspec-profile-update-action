control 'SV-34221' do
  title 'A form that is digitally signed must be displayed with a warning.'
  desc 'This setting controls whether the user sees a dialog box when opening Microsoft InfoPath forms containing digitally signed content. By default, InfoPath shows the user a warning message when the form contains a digital signature.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security “Display a warning that a form is digitally signed” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value SignatureWarning is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security “Display a warning that a form is digitally signed” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26621'
  tag rid: 'SV-34221r1_rule'
  tag stig_id: 'DTOO297 - InfoPath'
  tag gtitle: 'DTOO297 - A form is digitally signed'
  tag fix_id: 'F-29908r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
