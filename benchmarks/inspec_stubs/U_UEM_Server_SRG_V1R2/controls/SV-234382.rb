control 'SV-234382' do
  title 'The UEM server must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk. 

For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431026'
  desc 'check', 'Verify the UEM server obscures feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.

If the UEM server does not obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals, this is a finding.'
  desc 'fix', 'Configure the UEM server to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37567r614156_chk'
  tag severity: 'medium'
  tag gid: 'V-234382'
  tag rid: 'SV-234382r879615_rule'
  tag stig_id: 'SRG-APP-000178-UEM-000109'
  tag gtitle: 'SRG-APP-000178'
  tag fix_id: 'F-37532r614157_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
