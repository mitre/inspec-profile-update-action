control 'SV-217406' do
  title 'The BIG-IP appliance must be configured to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the network device must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk. For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'Verify if the BIG-IP appliance is configured to obscure feedback of authentication information during the authentication process.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Encryption" is configured to use SSL for the authentication process with a properly configured authentication server.

If the BIG-IP appliance is not configured to obscure feedback of authentication information during the authentication process, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use SSL communications when connecting to a properly configured authentication server.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18631r290772_chk'
  tag severity: 'medium'
  tag gid: 'V-217406'
  tag rid: 'SV-217406r879615_rule'
  tag stig_id: 'F5BI-DM-000133'
  tag gtitle: 'SRG-APP-000178-NDM-000264'
  tag fix_id: 'F-18629r290773_fix'
  tag 'documentable'
  tag legacy: ['SV-74593', 'V-60163']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
