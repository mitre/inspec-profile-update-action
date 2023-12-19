control 'SV-24772' do
  title 'Access to DBMS system tables and other configuration or metadata should be restricted to DBAs.'
  desc 'System tables and DBA views contain information such as user, system and data that could lead to unauthorized access. Revoke any privileges granted to non-DBA accounts that provide direct access to objects owned by SYS or access to DBA views (DBA_%).'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee, privilege, owner, table_name from dba_tab_privs
  where (owner='SYS' or table_name like 'DBA_%') 
  and privilege <> 'EXECUTE'
  and grantee not in
  ('PUBLIC', 'AQ_ADMINISTRATOR_ROLE', 'AQ_USER_ROLE',
   'AURORA$JIS$UTILITY$', 'OSE$HTTP$ADMIN', 'TRACESVR',
   'CTXSYS', 'DBA', 'DELETE_CATALOG_ROLE',
   'EXECUTE_CATALOG_ROLE', 'EXP_FULL_DATABASE',
   'GATHER_SYSTEM_STATISTICS', 'HS_ADMIN_ROLE',
   'IMP_FULL_DATABASE', 'LOGSTDBY_ADMINISTRATOR', 'MDSYS',
   'ODM', 'OEM_MONITOR', 'OLAPSYS', 'ORDSYS', 'OUTLN',
   'RECOVERY_CATALOG_OWNER', 'SELECT_CATALOG_ROLE',
   'SNMPAGENT', 'SYSTEM', 'WKSYS', 'WKUSER', 'WMSYS',
   'WM_ADMIN_ROLE', 'XDB', 'LBACSYS', 'PERFSTAT', 'XDBADMIN')
  and grantee not in
  (select grantee from dba_role_privs where granted_role='DBA')
  order by grantee;

If no accounts or roles are listed, this is not a Finding. 
 
Verify that accounts/roles listed have been authorized by the IAO.

NOTE: Any accounts created and assigned privileges by Oracle product installations do not require authorization by the IAO. The exclusion list provided in this check is subject to changes or additions made by updates to Oracle products. Non-Oracle products should not be assigned access to Oracle system data and tables, however, if required, document requirement in the System Security Plan and ensure authorization by the IAO."
  desc 'fix', 'Revoke unauthorized access to system tables and data.  

From SQL*Plus:
  revoke [object privilege] on [system object name] from [account name or role];'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29354r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15631'
  tag rid: 'SV-24772r2_rule'
  tag stig_id: 'DG0123-ORACLE11'
  tag gtitle: 'DBMS Administrative data access'
  tag fix_id: 'F-26380r1_fix'
  tag responsibility: 'Database Administrator'
end
