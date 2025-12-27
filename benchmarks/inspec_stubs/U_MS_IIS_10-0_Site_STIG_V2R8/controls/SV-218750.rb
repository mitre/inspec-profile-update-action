control 'SV-218750' do
  title 'Anonymous IIS 10.0 website access accounts must be restricted.'
  desc 'Many of the security problems that occur are not the result of a user gaining access to files or data for which the user does not have permissions, but rather users are assigned incorrect permissions to unauthorized data. The files, directories, and data stored on the web server must be evaluated and a determination made concerning authorized access to information and programs on the server. Only authorized users and administrative accounts will be allowed on the host server in order to maintain the web server, applications, and review the server operations.'
  desc 'check', 'Check the account used for anonymous access to the website.

Follow the procedures below for each site hosted on the IIS 10.0 web server:
Open the IIS 10.0 Manager.

Double-click "Authentication" in the IIS section of the website’s Home Pane.

If Anonymous access is disabled, this is Not a Finding.

If Anonymous access is enabled, click "Anonymous Authentication".

Click "Edit" in the "Actions" pane.

If the "Specific user" radio button is enabled and an ID is specified in the adjacent control box, this is the ID being used for anonymous access. Note: account name.

If nothing is tied to "Specific User", this is Not a Finding.

Check privileged groups that may allow the anonymous account inappropriate membership:
Open "Server Manager" on the machine.

Expand Configuration.

Expand Local Users and Groups.

Click "Groups".

Review members of any of the following privileged groups:

Administrators
Backup Operators
Certificate Services (of any designation)
Distributed COM Users
Event Log Readers
Network Configuration Operators
Performance Log Users
Performance Monitor Users
Power Users
Print Operators
Remote Desktop Users
Replicator

Double-click each group and review its members.

If the IUSR account or any account noted above used for anonymous access is a member of any group with privileged access, this is a finding.'
  desc 'fix', 'Remove the Anonymous access account from all privileged accounts and all privileged groups.'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20223r810856_chk'
  tag severity: 'high'
  tag gid: 'V-218750'
  tag rid: 'SV-218750r879631_rule'
  tag stig_id: 'IIST-SI-000221'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-20221r311149_fix'
  tag 'documentable'
  tag legacy: ['SV-109325', 'V-100221']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
