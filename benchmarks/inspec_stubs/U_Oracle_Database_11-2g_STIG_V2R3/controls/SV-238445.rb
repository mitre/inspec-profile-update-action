control 'SV-238445' do
  title 'Administrators must utilize a separate, distinct administrative account when performing administrative activities, accessing database security functions, or accessing security-relevant information.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account. 

To limit exposure when operating from within a privileged account or role, the application must support organizational requirements that users of information system accounts, or roles, with access to organization-defined lists of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

When privileged activities are not separated from non-privileged activities, the database can be subject to unauthorized changes to settings and data that a standard user would not normally have access to, outside of an authorized maintenance session.'
  desc 'check', "Review permissions for objects owned by DBA or other administrative accounts.

If any objects owned by administrative accounts can be accessed by non-DBA/non-administrative users, either directly or indirectly, this is a finding.

Verify DBAs have separate administrative accounts.

If DBAs do not have a separate account for database administration purposes, this is a finding.

To list all objects owned by an administrative account that have had access granted to another account, run the query:

SELECT grantee, table_name, grantor, privilege from dba_tab_privs where owner= '<applicable account>';"
  desc 'fix', 'Revoke DBA privileges, and privileges to administer DBA-owned objects, from non-DBA accounts.

Provide separate accounts to DBA for database administration.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41656r667507_chk'
  tag severity: 'medium'
  tag gid: 'V-238445'
  tag rid: 'SV-238445r667509_rule'
  tag stig_id: 'O112-C2-004100'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-41615r667508_fix'
  tag 'documentable'
  tag legacy: ['V-52387', 'SV-66603']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
