control 'SV-233102' do
  title 'The container platform must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the container platform and its components, e.g., runtime, registry, and keystore, must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed is a method used in addressing this risk.

Displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', "Review container platform documentation and configuration to determine if any interfaces that are provided for authentication purposes display the user's password when it is typed into the data entry field. 

If authentication information is not obfuscated when entered, this is a finding."
  desc 'fix', 'Configure the container platform to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36038r601736_chk'
  tag severity: 'medium'
  tag gid: 'V-233102'
  tag rid: 'SV-233102r879615_rule'
  tag stig_id: 'SRG-APP-000178-CTR-000470'
  tag gtitle: 'SRG-APP-000178'
  tag fix_id: 'F-36006r600794_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
