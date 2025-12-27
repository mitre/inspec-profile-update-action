control 'SV-204712' do
  title 'The application server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Strong access controls are critical to securing the application server. Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) must be employed by the application server to control access between users (or processes acting on behalf of users) and objects (e.g., applications, files, records, processes, application domains) in the application server.

Without stringent logical access and authorization controls, an adversary may have the ability, with very little effort, to compromise the application server and associated supporting infrastructure.'
  desc 'check', 'Review application server product documentation and configuration to determine if the system enforces authorization requirements for logical access to the system in accordance with applicable policy.

If the application server is not configured to utilize access controls or follow access control policies, this is a finding.'
  desc 'fix', 'Configure the application server to enforce access control policies for logical access to the system in accordance with applicable policy.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4832r282783_chk'
  tag severity: 'medium'
  tag gid: 'V-204712'
  tag rid: 'SV-204712r508029_rule'
  tag stig_id: 'SRG-APP-000033-AS-000024'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-4832r282784_fix'
  tag 'documentable'
  tag legacy: ['SV-47025', 'V-35738']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
