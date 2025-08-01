control 'SV-24723' do
  title 'Database privileged role assignments should be restricted to IAO-authorized DBMS accounts.'
  desc 'Roles assigned privileges to perform DDL and/or system configuration actions in the database can lead to compromise of any data in the database as well as operation of the DBMS itself. Restrict assignment of privileged roles to authorized personnel and database accounts to help prevent unauthorized activity.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts and roles):

  select grantee||': '||granted_role from dba_role_privs 
  where grantee not in
  ('ANONYMOUS','AURORA$JIS$UTILITY$',
   'AURORA$ORB$UNAUTHENTICATED','CTXSYS','DBSNMP','DIP',
   'DMSYS','DVF','DVSYS','EXFSYS','LBACSYS','MDDATA','MDSYS',
   'MGMT_VIEW','ODM','ODM_MTR','OLAPSYS','ORDPLUGINS','ORDSYS',
   'OSE$HTTP$ADMIN','OUTLN','PERFSTAT','REPADMIN','RMAN',
   'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM','TRACESVR',
   'TSMSYS','WK_TEST','WKPROXY','WKSYS','WKUSER','WMSYS','XDB') 
  and grantee not in
   ('DBA', 'OLAP_USER', 'IP', 'ORASSO_PUBLIC',
    'PORTAL_PUBLIC', 'DATAPUMP_EXP_FULL_DATABASE',
    'DATAPUMP_IMP_FULL_DATABASE', 'EXP_FULL_DATABASE',
    'IMP_FULL_DATABASE', 'OLAP_DBA', 'EXECUTE_CATALOG_ROLE',
    'SELECT_CATALOG_ROLE', 'JAVASYSPRIV')
  and grantee not in 
   (select grantee from dba_role_privs where granted_role = 'DBA')
  and grantee not in (select distinct owner from dba_objects)
  and granted_role in 
  ('AQ_ADMINISTRATOR_ROLE','AQ_USER_ROLE',
   'CTXAPP',
   'DELETE_CATALOG_ROLE','EJBCLIENT','EXECUTE_CATALOG_ROLE',
   'EXP_FULL_DATABASE','GATHER_SYSTEM_STATISTICS',
   'GLOBAL_AQ_USER_ROLE','HS_ADMIN_ROLE',
   'IMP_FULL_DATABASE','JAVADEBUGPRIV','JAVAIDPRIV',
   'JAVASYSPRIV','JAVAUSERPRIV','JAVA_ADMIN','JAVA_DEPLOY',
   'LOGSTDBY_ADMINISTRATOR','OEM_MONITOR','OLAP_DBA',
   'RECOVERY_CATALOG_OWNER',
   'SALES_HISTORY_ROLE','SELECT_CATALOG_ROLE','WKUSER',
   'WM_ADMIN_ROLE','XDBADMIN') 
  and granted_role not in ('CONNECT', 'RESOURCE', 'AUTHENTICATEDUSER')
  order by grantee;

If any records are returned, confirm the grantee and role are documented in the System Security Plan and authorized by the IAO.

If not documented and approved, this is a Finding."
  desc 'fix', 'Create custom roles for each discrete application user / administrator function required for your database and assign the minimum privileges necessary to perform the function.

Assign custom roles to accounts.

Revoke assignment of predefined roles from accounts where not documented in the System Security Plan and authorized by the IAO.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-953r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15626'
  tag rid: 'SV-24723r2_rule'
  tag stig_id: 'DG0116-ORACLE11'
  tag gtitle: 'DBMS privileged role assignments'
  tag fix_id: 'F-3783r1_fix'
  tag responsibility: 'Information Assurance Officer'
end
