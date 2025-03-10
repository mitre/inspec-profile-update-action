control 'SV-32381' do
  title 'Anonymous access accounts must be restricted.'
  desc 'Many of the security problems that occur are not the result of a user gaining access to files or data for which the user does not have permissions, but rather users are assigned incorrect permissions to unauthorized data. The files, directories, and data that are stored on the web server need to be evaluated and a determination made concerning authorized access to information and programs on the server. Only authorized users and administrative accounts will be allowed on the host server in order to maintain the web server, applications, and review the server operations.'
  desc 'check', 'Check the account used for anonymous access to the web site.
1. Open the IIS Manager.
2. Click the site being reviewed.
3. Double-click Authentication in the IIS section of the web site’s Home Pane.
If Anonymous access is disabled, this check may end here, and is considered not a finding.
4. If enabled, left-click Anonymous Authentication, and then left-click Edit in the Actions pane.
5. If the Specific user radio button is enabled and an ID is specified in the adjacent control box, this is the ID being used for anonymous access.

Check privileged groups that may allow the anonymous account inappropriate membership.
1. Left-click Start and then double-click Server Manager.
2. Expand Configuration; expand Local Users and Groups; and then left-click Groups.
3. Review group members.
Privileged Groups:
Administrators
Backup Operators
Certificate Services (of any designation)
Distributed COM users
Event Log Readers
Network Configuration Operators\\Performance Log Users
Performance Monitor Users
Power Users
Print Operators
Remote Desktop Users
Replicator
Users
4. Double-click each group and review its members.  

If the IUSR account or any account used for anonymous access is a member of any group with privileged access, this is a finding.'
  desc 'fix', 'Remove the Anonymous access account from all privileged accounts and all privileged groups.'
  impact 0.7
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32771r1_chk'
  tag severity: 'high'
  tag gid: 'V-6537'
  tag rid: 'SV-32381r2_rule'
  tag stig_id: 'WG195 IIS7'
  tag gtitle: 'WG195'
  tag fix_id: 'F-29070r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
