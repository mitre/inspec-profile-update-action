control 'SV-204709' do
  title 'The application server must use encryption strength in accordance with the categorization of the management data during remote access management sessions.'
  desc 'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. 

Types of management interfaces utilized by an application server include web-based HTTPS interfaces as well as command line-based management interfaces.'
  desc 'check', 'Check the application server configuration to ensure all management interfaces use encryption in accordance with the management data.

If the application server is not configured to encrypt remote access management sessions in accordance with the categorization of the management data, this is a finding.'
  desc 'fix', 'Configure the application server to use encryption strength in accordance with the categorization of the management data during remote access management sessions.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4829r282774_chk'
  tag severity: 'medium'
  tag gid: 'V-204709'
  tag rid: 'SV-204709r508029_rule'
  tag stig_id: 'SRG-APP-000014-AS-000009'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-4829r282775_fix'
  tag 'documentable'
  tag legacy: ['SV-46376', 'V-35089']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
