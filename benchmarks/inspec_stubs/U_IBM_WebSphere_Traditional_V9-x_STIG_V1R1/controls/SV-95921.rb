control 'SV-95921' do
  title 'The WebSphere Application Server users in the WebSphere auditor role must be configured in accordance with the System Security Plan.'
  desc 'Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.

Remote access by administrators requires that the admin activity be logged.

Application servers provide a web and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.

'
  desc 'check', 'Review System Security Plan documentation.

Identify users and roles.

In the administrative console, navigate to Users and Groups >> Administrative User Roles.

Check the roles for each user.

If any user is not authorized by the ISSO/ISSM to be in the role of an auditor, this is a finding.'
  desc 'fix', 'In the administrative console, navigate to Users and Groups >> Administrative User roles.

If an unauthorized user is in the auditor role, remove the user from the auditor role.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81207'
  tag rid: 'SV-95921r1_rule'
  tag stig_id: 'WBSP-AS-000090'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-87985r1_fix'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000343-AS-000030', 'SRG-APP-000090-AS-000051']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000171', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-12 b', 'AC-6 (9)']
end
