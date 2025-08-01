control 'SV-95919' do
  title 'The WebSphere Application Server groups in the user registry mapped to WebSphere auditor roles must be configured in accordance with the security plan.'
  desc 'Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.

Remote access by administrators requires that the admin activity be logged.

Application servers provide a web and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.

'
  desc 'check', 'Review System Security Plan documentation.

Identify groups and roles.

In the administrative console, navigate to Users and Groups >> Administrative Group Roles.

Check the roles for each group and compare to System Security Plan.

If any group is not authorized by the ISSO/ISSM to be in an auditor role, this is a finding.'
  desc 'fix', 'Document all groups in an Auditor role in the security plan.

In the administrative console, navigate to Users and Groups >> Administrative group roles.

If an unauthorized group is in the auditor role, remove the auditor role from the group.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81205'
  tag rid: 'SV-95919r1_rule'
  tag stig_id: 'WBSP-AS-000080'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-87983r1_fix'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000343-AS-000030']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AC-6 (9)']
end
