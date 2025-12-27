control 'SV-53415' do
  title 'OS and domain accounts utilized to run external procedures called by SQL Server must have limited privileges.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role-Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account.

To limit exposure when operating from within a privileged account or role, the application must support organizational requirements that users of information system accounts, or roles, with access to an organization-defined list of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

Use of privileged accounts for non-administrative purposes puts data at risk of unintended or unauthorized loss, modification, or exposure. In particular, DBA accounts, if used for non-administration application development or application maintenance, can lead to misassignment of privileges where privileges are inherited by object owners. It may also lead to loss or compromise of application data where the elevated privileges bypass controls designed in, and provided by, applications.

External applications called by SQL Server may be executed under OS or domain accounts with unnecessary privileges. This can lead to unauthorized access to OS resources and compromise of the OS, SQL Server, or any other services provided by the host platform.'
  desc 'check', 'Determine which OS or domain accounts are used by SQL Server to run external procedures. Validate that these accounts have only the privileges necessary to perform the required functionality.

If any OS or domain accounts utilized by SQL Server are running external procedures and have privileges beyond those required for running the external procedures, this is a finding.'
  desc 'fix', 'Limit privileges to SQL Server-related OS and domain accounts to those required privileges needed to perform their SQL Server-specific functionality.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47657r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41040'
  tag rid: 'SV-53415r3_rule'
  tag stig_id: 'SQL2-00-009900'
  tag gtitle: 'SRG-APP-000063-DB-000020'
  tag fix_id: 'F-46339r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
