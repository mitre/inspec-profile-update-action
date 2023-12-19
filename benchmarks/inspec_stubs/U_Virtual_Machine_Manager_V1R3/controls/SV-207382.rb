control 'SV-207382' do
  title 'The VMM must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information, such as passwords during the authentication process, the feedback from the VMM shall not provide any information allowing an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided information that is typed into the system is a method used when addressing this risk. 

For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'Verify the VMM obscures feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7639r365556_chk'
  tag severity: 'medium'
  tag gid: 'V-207382'
  tag rid: 'SV-207382r378769_rule'
  tag stig_id: 'SRG-OS-000079-VMM-000460'
  tag gtitle: 'SRG-OS-000079'
  tag fix_id: 'F-7639r365557_fix'
  tag 'documentable'
  tag legacy: ['SV-71215', 'V-56955']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
