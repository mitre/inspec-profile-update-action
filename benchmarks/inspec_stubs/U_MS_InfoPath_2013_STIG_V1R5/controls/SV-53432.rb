control 'SV-53432' do
  title 'A form that is digitally signed must be displayed with a warning.'
  desc 'This setting controls whether or not the user sees a dialog box when opening Microsoft InfoPath forms containing digitally signed content. By default, InfoPath shows the user a warning message when the form contains a digital signature. By being aware of a digitally signed form, the user will be able to check the validity of the signature. Otherwise, the forms may have been maliciously modified and will be invalidated.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security "Display a warning that a form is digitally signed" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value SignatureWarning is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security "Display a warning that a form is digitally signed" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26621'
  tag rid: 'SV-53432r1_rule'
  tag stig_id: 'DTOO297'
  tag gtitle: 'DTOO297 - A form is digitally signed'
  tag fix_id: 'F-46356r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
