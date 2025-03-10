control 'SV-204752' do
  title 'The application server must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.  If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Application servers have the capability to utilize either certificates (tokens) or user IDs and passwords in order to authenticate. When the application server transmits or receives passwords, the passwords must be encrypted.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server enforces the requirement to encrypt passwords when they are transmitted.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to transmit only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4872r282903_chk'
  tag severity: 'medium'
  tag gid: 'V-204752'
  tag rid: 'SV-204752r508029_rule'
  tag stig_id: 'SRG-APP-000172-AS-000120'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-4872r282904_fix'
  tag 'documentable'
  tag legacy: ['SV-46605', 'V-35318']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
