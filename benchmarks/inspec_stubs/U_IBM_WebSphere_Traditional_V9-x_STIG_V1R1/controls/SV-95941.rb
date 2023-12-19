control 'SV-95941' do
  title 'The WebSphere Application Server users in the admin role must be authorized.'
  desc 'Strong access controls are critical to securing the application server. Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) must be employed by the application server to control access between users (or processes acting on behalf of users) and objects (e.g., applications, files, records, processes, application domains) in the application server.

Without stringent logical access and authorization controls, an adversary may have the ability, with very little effort, to compromise the application server and associated supporting infrastructure.

'
  desc 'check', 'Review System Security Plan documentation.

In the administrative console, navigate to Users and Groups >> Administrative user roles.

If users assigned to the admin role are not authorized by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'Navigate to User and Groups >> Administrative user roles.

If an unauthorized user is assigned to the admin role, click on the user, remove admin rights and assign proper roles as defined in System Security Plan.

Do not delete any user with the "Primary administrative user name" designation.

Click "OK".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81227'
  tag rid: 'SV-95941r1_rule'
  tag stig_id: 'WBSP-AS-000220'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-88007r1_fix'
  tag satisfies: ['SRG-APP-000033-AS-000024', 'SRG-APP-000380-AS-000088', 'SRG-APP-000340-AS-000185']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001813', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (1) (a)', 'AC-6 (10)']
end
