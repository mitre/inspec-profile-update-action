control 'SV-24755' do
  title 'Application users privileges should be restricted to assignment using application user roles.'
  desc 'Granting permissions to accounts is error prone and repetitive. Using roles allows for group management of privileges assigned by function and reduces the likelihood of wrongfully assigned privileges. Assign permissions to roles and then grant the roles to accounts.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee||': '||privilege||': '||owner||'.'||table_name 
  from dba_tab_privs where grantee not in
  (select role from dba_roles)
  and grantee not in
  ('APEX_PUBLIC_USER', 'AURORA$JIS$UTILITY$', 'CTXSYS',
   'DBSNMP', 'EXFSYS', 'FLOWS_030000', 'FLOWS_FILES',
   'LBACSYS', 'MDSYS', 'MGMT_VIEW', 'ODM', 'OLAPSYS',
   'ORACLE_OCM', 'ORDPLUGINS', 'ORDSYS',
   'OSE$HTTP$ADMIN', 'OUTLN', 'OWBSYS', 'PERFSTAT',
   'PUBLIC', 'REPADMIN', 'SYS', 'SYSMAN', 'SYSTEM',
   'WKSYS', 'WMSYS', 'XDB')
  and table_name<>'DBMS_REPCAT_INTERNAL_PACKAGE'
  and table_name not like '%RP'
  and grantee not in
  (select grantee from dba_tab_privs
   where table_name in ('DBMS_DEFER', 'DEFLOB'));

If any records are returned, this is a Finding.

NOTE:  This check may report false positives where other ORACLE products have been installed. Accounts installed with other Oracle products are exempt from this requirement."
  desc 'fix', 'Revoke privileges assigned directly to database accounts and assign them to roles based on job functions.

Assign users who are assigned responsibility for the job function to the defined role.

From SQL*Plus:
  revoke [privilege] on [object name] from [user name];
  grant [privilege] on [object name] to [role name];'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1002r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15629'
  tag rid: 'SV-24755r2_rule'
  tag stig_id: 'DG0121-ORACLE11'
  tag gtitle: 'DBMS application user privilege assignment'
  tag fix_id: 'F-3792r1_fix'
  tag false_positives: 'NOTE: This check may report false positives where other ORACLE products have been installed. Accounts installed with other Oracle products are exempt from this requirement.'
  tag responsibility: 'Database Administrator'
end
