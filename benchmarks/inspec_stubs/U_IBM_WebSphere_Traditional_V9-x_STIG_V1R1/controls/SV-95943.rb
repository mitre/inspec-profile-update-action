control 'SV-95943' do
  title 'The WebSphere Application Server LDAP groups must be authorized for the WebSphere role.'
  desc 'Strong access controls are critical to securing the application server. Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) must be employed by the application server to control access between users (or processes acting on behalf of users) and objects (e.g., applications, files, records, processes, application domains) in the application server.

Without stringent logical access and authorization controls, an adversary may have the ability, with very little effort, to compromise the application server and associated supporting infrastructure.

'
  desc 'check', 'Review System Security Plan documentation.

Review details regarding LDAP groups that are mapped to WebSphere roles. 

In the administrative console, under Users and Groups >> Administrative group roles.

If there is a LDAP group or groups assigned to a WebSphere role that has not been authorized by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'Navigate to User and Groups >> Administrative group roles.

If any group is assigned roles that the group should not have, click on the group.

Assign only the role(s) the group should have.

Click "OK".

Click "Save". 

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81229'
  tag rid: 'SV-95943r1_rule'
  tag stig_id: 'WBSP-AS-000230'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-88009r1_fix'
  tag satisfies: ['SRG-APP-000033-AS-000024', 'SRG-APP-000267-AS-000170']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001314']
  tag nist: ['AC-3', 'SI-11 b']
end
