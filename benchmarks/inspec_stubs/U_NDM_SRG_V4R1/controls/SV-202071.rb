control 'SV-202071' do
  title 'The network device must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the network device must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.  For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'Determine if the network device obscures feedback of authentication information during the authentication process.  This requirement may be verified by demonstration. If the network device does not obscure feedback of authentication information during the authentication process, this is a finding.'
  desc 'fix', 'Configure the network device to obscure feedback of authentication information during the authentication process.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2197r381833_chk'
  tag severity: 'high'
  tag gid: 'V-202071'
  tag rid: 'SV-202071r397603_rule'
  tag stig_id: 'SRG-APP-000178-NDM-000264'
  tag gtitle: 'SRG-APP-000178'
  tag fix_id: 'F-2198r381834_fix'
  tag 'documentable'
  tag legacy: ['SV-69395', 'V-55149']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
