control 'SV-24746' do
  title 'DBMS application users should not be granted administrative privileges to the DBMS.'
  desc 'Excessive privileges can lead to unauthorized actions on data and database objects. Assigning only the privileges required to perform the job function authorized for the user helps protect against exploits against application vulnerabilities such as SQL injection attacks. The recommended method is to grant access only to stored procedures that perform only static actions on the data authorized for the user. Where this is not feasible, consider using data views or other methods to restrict users to only the data suitable for their job function.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee, owner, table_name, privilege from dba_tab_privs
  where privilege in ('ALTER', 'REFERENCES', 'INDEX')
  and grantee not in ('DBA', 'SYS', 'SYSTEM', 'LBACSYS', 'XDBADMIN')
  and table_name not in
  ('SDO_IDX_TAB_SEQUENCE', 'XDB$ACL', 'XDB_ADMIN')
  and grantee not in
  (select grantee from dba_role_privs where granted_role = 'DBA')
  and grantee not in (select distinct owner from dba_objects);

If any records are returned, this is a Finding."
  desc 'fix', 'Revoke ALTER, REFERENCES, and INDEX privileges from application user roles.

From SQL*Plus:
  revoke [privilege] from [application user role];

Replace [privilege] with the identified ALTER, REFERENCES or INDEX privilege and [application user role] with the identified application role.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15628'
  tag rid: 'SV-24746r2_rule'
  tag stig_id: 'DG0119-ORACLE11'
  tag gtitle: 'DBMS application user role privileges'
  tag fix_id: 'F-3788r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
