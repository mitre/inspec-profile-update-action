control 'SV-24395' do
  title 'Developers should not be assigned excessive privileges on production databases.'
  desc 'Developers play a unique role and represent a specific type of threat to the security of the DBMS.  Where restricted resources prevent the required separation of production and development DBMS installations, developers granted elevated privileges to create and manage new database objects must also be prevented from actions that can threaten the production operation.'
  desc 'check', 'If this database is not a production database, this check is Not a Finding.

Review the privileges assigned to developer accounts.

Identify login name of developer DBMS accounts from the System Security Plan and/or DBA.

For each developer account, display the roles assigned to the account.

From SQL*Plus:
  select granted_role from dba_role_privs where grantee=[developer account name];

If privileges assigned to developer accounts are not restricted to development objects and configurations, or authorizations to allow developer account access to production objects and configurations does not exist in the System Security Plan, this is a Finding.'
  desc 'fix', 'Revoke permissions and privileges that allow changes to the production system or production objects from developer accounts or authorize permissions and privileges for developer accounts in the System Security Plan.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-19608r1_chk'
  tag severity: 'low'
  tag gid: 'V-15114'
  tag rid: 'SV-24395r1_rule'
  tag stig_id: 'DG0089-ORACLE11'
  tag gtitle: 'Developer DBMS privileges on production databases'
  tag fix_id: 'F-2590r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
