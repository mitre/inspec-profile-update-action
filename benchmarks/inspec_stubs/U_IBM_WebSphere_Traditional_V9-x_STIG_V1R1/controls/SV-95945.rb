control 'SV-95945' do
  title 'The WebSphere Application Server users in a LDAP user registry group must be authorized for that group.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Restricting non-privileged users also prevents an attacker, who has gained access to a non-privileged account, from elevating privileges, creating accounts, and performing system checks and maintenance.'
  desc 'check', 'If a file based or local federated repository is in use, this requirement is NA.

Review System Security Plan documentation.

Interview the system administrator.

In the administrative console select Security >> Global Security.

Under "User Account Repository", verify the "Available realm Definition" is set to "Standalone LDAP registry".

Select "Configure".

The properties of the LDAP repository are displayed for purposes of identifying the LDAP server.

Work with the admin of LDAP repository.

Identify users and groups.

Validate members of groups are authorized.

If the group members have not been authorized by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'In the LDAP server admin console, assign WebSphere users to the appropriate WebSphere group.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80911r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81231'
  tag rid: 'SV-95945r1_rule'
  tag stig_id: 'WBSP-AS-000240'
  tag gtitle: 'SRG-APP-000340-AS-000185'
  tag fix_id: 'F-88011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
