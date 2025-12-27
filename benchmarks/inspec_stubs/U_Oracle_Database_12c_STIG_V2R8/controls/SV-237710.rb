control 'SV-237710' do
  title 'Administrators must utilize a separate, distinct administrative account when performing administrative activities, accessing database security functions, or accessing security-relevant information.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account.

To limit exposure when operating from within a privileged account or role, the application must support organizational requirements that users of information system accounts, or roles, with access to organization-defined lists of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

When privileged activities are not separated from non-privileged activities, the database can be subject to unauthorized changes to settings and data that a standard user would not normally have access to, outside of an authorized maintenance session.'
  desc 'check', "Review permissions for objects owned by DBA or other administrative accounts.

If any objects owned by administrative accounts can be accessed by non-DBA/non-administrative users, either directly or indirectly, this is a finding.

Verify DBAs have separate administrative accounts.

If DBAs do not have a separate account for database administration purposes, this is a finding.

To list all objects owned by an administrative account that have had access granted to another account, run the query:

SELECT grantee, table_name, grantor, privilege, type from dba_tab_privs where owner= '<applicable account>';"
  desc 'fix', 'Revoke DBA privileges, and privileges to administer DBA-owned objects, from non-DBA accounts.

Provide separate accounts to DBA for database administration.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40929r667160_chk'
  tag severity: 'medium'
  tag gid: 'V-237710'
  tag rid: 'SV-237710r879643_rule'
  tag stig_id: 'O121-C2-004100'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-40892r667161_fix'
  tag 'documentable'
  tag legacy: ['V-61593', 'SV-76083']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
