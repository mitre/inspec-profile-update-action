control 'SV-24534' do
  title 'Oracle system privileges should not be directly assigned to unauthorized accounts.'
  desc 'System privileges allow system-wide changes to the database or database objects. Unauthorized use of system privileges may jeopardize production applications, application data, or the database configuration and operation.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee||': '||PRIVILEGE from dba_sys_privs
  where privilege<>'CREATE SESSION'
  and grantee not in
  ('PUBLIC', 'AQ_ADMINISTRATOR_ROLE', 'AQ_USER_ROLE', 'CTXSYS',
   'DBA', 'DELETE_CATALOG_ROLE', 'EXECUTE_CATALOG_ROLE',
   'EXP_FULL_DATABASE', 'GATHER_SYSTEM_STATISTICS',
   'HS_ADMIN_ROLE', 'IMP_FULL_DATABASE',
   'LOGSTDBY_ADMINISTRATOR', 'MDSYS', 'ODM', 'OEM_MONITOR',
   'OLAPSYS', 'ORDSYS', 'OUTLN', 'MTSSYS',
   'RECOVERY_CATALOG_OWNER', 'SELECT_CATALOG_ROLE',
   'SNMPAGENT', 'SYSTEM', 'WKSYS', 'WKUSER', 'WMSYS',
   'WM_ADMIN_ROLE', 'XDB', 'ANONYMOUS', 'CONNECT', 'DBSNMP',
   'JAVADEBUGPRIV', 'ODM_MTR', 'OLAP_DBA', 'ORDPLUGINS',
   'RESOURCE', 'RMAN', 'SYS', 'WKPROXY', 'AURORA$JIS$UTILITY$',
   'AURORA$ORB$UNAUTHENTICATED', 'OSE$HTTP$ADMIN',
   'TIMESERIES_DBA', 'TIMESERIES_DEVELOPER', 'OLAP_USER')
  and grantee not in
  (select grantee from dba_role_privs where granted_role='DBA')
  and grantee not in
  (select username from dba_users where upper(account_status) like
   '%LOCKED%');

If any records are returned, perform the following instructions for this check to determine the finding status.

Review the list of active non-DBA accounts and roles granted system privileges.

Any accounts listed as authorized for checks DO0340 (Oracle application administration roles enablement) and DG0008 (Oracle object ownership) are not a Finding.

On a production database, confirm that any accounts listed with create user, alter user, drop user belong to authorized application administration roles.

On a development system, ensure that system privileges assigned to developers are justified and authorized by the IAO.

If any unauthorized, unjustified or undocumented application user roles or accounts are listed, this is a Finding."
  desc 'fix', 'Document and justify system privileges assigned to users/roles in the System Security Plan and authorize with the IAO.

Remove unauthorized or unjustified system privileges from user accounts or roles.

From SQL*Plus:

  revoke [privilege] from [user or role name];

Replace [privilege] with the named privilege and [user or role name] with the identified user or role.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29451r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3439'
  tag rid: 'SV-24534r2_rule'
  tag stig_id: 'DO0350-ORACLE11'
  tag gtitle: 'Oracle system privilege assignment'
  tag fix_id: 'F-26515r1_fix'
  tag responsibility: 'Information Assurance Officer'
end
