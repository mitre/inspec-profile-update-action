control 'SV-204757' do
  title 'The application server must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information during the authentication process, the application server authentication screens must obfuscate input so an unauthorized user cannot view a password, PIN, or any other authenticator value as it is being typed.

This can occur when a user is authenticating to the application server through the web management interface or command line interface. The application server must obfuscate all passwords, PINs, or other authenticator information when typed. User ID is not required to be obfuscated.'
  desc 'check', "Review the application server documentation and configuration to determine if any interfaces which are provided for authentication purposes display the user's password when it is typed into the data entry field.

If authentication information is not obfuscated when entered, this is a finding."
  desc 'fix', 'Configure the application server to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4877r282918_chk'
  tag severity: 'medium'
  tag gid: 'V-204757'
  tag rid: 'SV-204757r508029_rule'
  tag stig_id: 'SRG-APP-000178-AS-000127'
  tag gtitle: 'SRG-APP-000178'
  tag fix_id: 'F-4877r282919_fix'
  tag 'documentable'
  tag legacy: ['V-35328', 'SV-46615']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
