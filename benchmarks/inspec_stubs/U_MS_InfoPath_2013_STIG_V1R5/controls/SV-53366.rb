control 'SV-53366' do
  title 'Disabling sending form templates with the email forms must be configured.'
  desc 'InfoPath allows users to attach form templates when sending email forms. If users are able to open form templates included with email forms, rather than using a cached version that is previously published, an attacker could send a malicious form template with the email form in an attempt to gain access to sensitive information.
Note: The form template is only opened directly if the form opens with a restricted security level. Otherwise, the attachment is actually a link to the published location.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable sending form template with e-mail forms" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\deployment

Criteria: If the value MailXSNwithXML is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Disable sending form template with e-mail forms" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17667'
  tag rid: 'SV-53366r1_rule'
  tag stig_id: 'DTOO168'
  tag gtitle: 'DTOO168 - Sending templates with email form'
  tag fix_id: 'F-46292r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
