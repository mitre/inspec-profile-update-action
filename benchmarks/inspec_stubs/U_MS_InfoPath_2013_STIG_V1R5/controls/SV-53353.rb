control 'SV-53353' do
  title 'Disabling of Fully Trusted Solutions access to computers must be configured.'
  desc "InfoPath users can choose whether to allow trusted forms to run on their computers. The Full Trust security level allows a form to access local system resources, such as COM components or files on users' computers, and suppresses certain security prompts. It can only be used with forms that are installed on users' computers or with forms using a form template that is digitally signed with a trusted root certificate.
As with any security model that allows trusted entities to operate with fewer security controls, if a form with malicious content is marked as fully trusted it could be used to compromise information security or affect users' computers."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security -> "Disable fully trusted solutions full access to computer" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value RunFullTrustSolutions is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security -> "Disable fully trusted solutions full access to computer" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47618r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17658'
  tag rid: 'SV-53353r1_rule'
  tag stig_id: 'DTOO159'
  tag gtitle: 'DTOO159 - Fully trusted solutions access'
  tag fix_id: 'F-46280r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
