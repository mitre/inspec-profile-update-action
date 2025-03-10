control 'SV-95927' do
  title 'The WebSphere Application Server users in a local user registry group must be authorized for that group.'
  desc 'Application servers provide remote access capability and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. Automated monitoring and control of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by logging connection activities of remote users.

Examples of policy requirements include, but are not limited to, authorizing remote access to the information system, limiting access based on authentication credentials, and monitoring for unauthorized access.

'
  desc 'check', 'If the systems user registry is managed by LDAP, this requirement is NA.

Review the System Security Plan documentation.

Interview the system administrator.

Obtain a list of authorized users.

In the administrative console, navigate to Users and Groups >> Manage Groups.

Select each group.

Select the "Members" tab.

Validate the members of the group are authorized.

If users in the group are not authorized by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'From administrative console, navigate to Users and Groups >> Administrative group roles.

Note: names of the groups and the roles assigned to each group.

Navigate back to User and Groups >> Manage Groups.

Click on every group.

For each group, click on users.

If there is any user who does not belong to the group based on the roles assigned to the group, click on the checkbox next to the user.

Click "Remove".

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80883r3_chk'
  tag severity: 'medium'
  tag gid: 'V-81213'
  tag rid: 'SV-95927r1_rule'
  tag stig_id: 'WBSP-AS-000150'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-87991r2_fix'
  tag satisfies: ['SRG-APP-000315-AS-000094', 'SRG-APP-000380-AS-000088', 'SRG-APP-000133-AS-000092', 'SRG-APP-000033-AS-000024', 'SRG-APP-000153-AS-000104']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000770', 'CCI-001499', 'CCI-001813', 'CCI-002314']
  tag nist: ['AC-3', 'IA-2 (5)', 'CM-5 (6)', 'CM-5 (1) (a)', 'AC-17 (1)']
end
