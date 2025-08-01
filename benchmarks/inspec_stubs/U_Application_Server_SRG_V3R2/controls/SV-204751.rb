control 'SV-204751' do
  title 'The application server must store only encrypted representations of passwords.'
  desc 'Applications must enforce password encryption when storing passwords. Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read and easily compromised. 

Application servers provide either a local user store or they integrate with enterprise user stores like LDAP. When the application server is responsible for creating or storing passwords, the application server must enforce the storage of encrypted representations of passwords.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server enforces the requirement to only store encrypted representations of passwords.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to only store encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4871r282900_chk'
  tag severity: 'medium'
  tag gid: 'V-204751'
  tag rid: 'SV-204751r508029_rule'
  tag stig_id: 'SRG-APP-000171-AS-000119'
  tag gtitle: 'SRG-APP-000171'
  tag fix_id: 'F-4871r282901_fix'
  tag 'documentable'
  tag legacy: ['SV-46604', 'V-35317']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
