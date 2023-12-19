control 'SV-203635' do
  title 'The operating system must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information, such as passwords during the authentication process, the feedback from the operating system shall not provide any information allowing an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information that is typed into the system is a method used when addressing this risk.

For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'Verify the operating system obscures feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3760r557629_chk'
  tag severity: 'medium'
  tag gid: 'V-203635'
  tag rid: 'SV-203635r557631_rule'
  tag stig_id: 'SRG-OS-000079-GPOS-00047'
  tag gtitle: 'SRG-OS-000079'
  tag fix_id: 'F-3760r557630_fix'
  tag 'documentable'
  tag legacy: ['V-56745', 'SV-71005']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
