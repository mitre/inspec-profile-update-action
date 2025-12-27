control 'SV-96005' do
  title 'The Central Log Server must obfuscate authentication information during the authentication process so that the authentication is not visible.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk. 

For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to obfuscate authentication information during the authentication process so that the authentication is not visible.

If the Central Log Server is not configured to obfuscate authentication information during the authentication process so that the authentication is not visible, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to obfuscate authentication information during the authentication process so that the authentication is not visible to protect the information from possible exploitation/use by unauthorized individuals.'
  impact 0.7
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80993r1_chk'
  tag severity: 'high'
  tag gid: 'V-81291'
  tag rid: 'SV-96005r1_rule'
  tag stig_id: 'SRG-APP-000178-AU-002660'
  tag gtitle: 'SRG-APP-000178-AU-002660'
  tag fix_id: 'F-88073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
