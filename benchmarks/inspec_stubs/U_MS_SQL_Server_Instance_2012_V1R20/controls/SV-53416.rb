control 'SV-53416' do
  title 'SQL Server DBA roles must not be assigned excessive or unauthorized privileges.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role-Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account.

Audit of privileged activity may require physical separation, employing information systems on which the user does not have privileged access.

To limit exposure and provide forensic history of activity when operating from within a privileged account or role, SQL Server does support organizational requirements that users of information system accounts, or roles, with access to an organization-defined list of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

SQL Server provides access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged. DBAs, if assigned excessive privileges, could perform actions that endanger the information system or hide evidence of malicious activity.'
  desc 'check', "Obtain the list of all DBAs.
Obtain documented role assignments for each DBA.
Obtain from system documentation or use SQL Server to determine privilege assignment of user-defined roles.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> User >> Securables.

If any item in the 'Permission' listing, for each highlighted item that exists in the 'Securables' listing, has excessive privileges, this is a finding.

Navigate from 'Securables' to 'Server Roles'.

If any checked 'Server roles' are determined to be excessive privileges, this is a finding.

Navigate from 'Server Roles' to 'Users mapped to the login'.

If any checked 'Database role membership' of each highlighted and checked 'Database' are determined to be excessive privileges, this is a finding."
  desc 'fix', "Remove permissions from DBAs and other administrative users beyond those required for administrative functions.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'administrator account name'> >> Properties >> User >> Securables.

Remove 'Securables' permissions from DBAs and other administrative users that are beyond what is required.

Navigate from 'Securables' to 'Server Roles'.

Remove 'Server Roles' permissions from DBAs and other administrative users that are beyond what is required.

Navigate from 'Server Roles' to 'Users mapped to the login'.

Remove 'Users mapped to the login' permissions from DBAs and other administrative users that are beyond what is required."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47658r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41041'
  tag rid: 'SV-53416r2_rule'
  tag stig_id: 'SQL2-00-009800'
  tag gtitle: 'SRG-APP-000063-DB-000019'
  tag fix_id: 'F-46340r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
