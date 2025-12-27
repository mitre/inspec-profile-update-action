control 'SV-24589' do
  title 'Application object owner accounts should be disabled when not performing installation or maintenance actions.'
  desc 'Object ownership provides all database object permissions to the owned object. Access to the application object owner accounts requires special protection to prevent unauthorized access and use of the object ownership privileges. In addition to the high privileges to application objects assigned to this account, it is also an account that, by definition, is not accessed interactively except for application installation and maintenance. This reduced access to the account means that unauthorized access to the account could go undetected. To help protect the account, it should be enabled only when access is required.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):
  select distinct owner from dba_objects, dba_users 
  where owner not in
  ('ANONYMOUS','AURORA$JIS$UTILITY$',
   'AURORA$ORB$UNAUTHENTICATED','CTXSYS','DBSNMP','DIP','DVF',
   'DVSYS','EXFSYS','LBACSYS','MDDATA','MDSYS','MGMT_VIEW','ODM',
   'ODM_MTR','OLAPSYS','ORDPLUGINS','ORDSYS','OSE$HTTP$ADMIN',
   'OUTLN','PERFSTAT','PUBLIC','REPADMIN','RMAN',
   'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM','TRACESVR',
   'TSMSYS','WK_TEST','WKPROXY','WKSYS','WKUSER','WMSYS','XDB')  
  and owner in (select distinct owner from dba_objects where object_type <> 'SYNONYM')
  and owner = username
  and upper(account_status) not like '%LOCKED%';

To obtain a list of users assigned DBA privileges.

From SQL*Plus:
  select grantee from dba_role_privs where granted_role = ’DBA’;

If any records are returned, then verify the account is an authorized application object owner account or a default account installed to support an Oracle product.  

Verify that any objects owned by custom DBA accounts are for the personal use of that DBA.

If any objects are used to support applications or any functions other than DBA functions, this is a Finding.

Any unauthorized object owner accounts are not a finding under this check as they are noted as findings under check DG0008.  

Any other accounts listed are a Finding."
  desc 'fix', 'Disable any application object owner accounts.

From SQL*Plus:
  alter user [username] account lock;

Enable application object owner accounts only for installation and maintenance.

DBA are special purpose accounts and do not require disabling although they may own objects.

For application objects that require routine maintenance, e.g. index objects, to maintain performance, consider allowing a special purpose account to own the index or enable the application owner account for the duration of the routine maintenance function only.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1073r2_chk'
  tag severity: 'medium'
  tag gid: 'V-5683'
  tag rid: 'SV-24589r2_rule'
  tag stig_id: 'DG0004-ORACLE11'
  tag gtitle: 'DBMS application object owner accounts'
  tag fix_id: 'F-15683r1_fix'
  tag responsibility: 'Database Administrator'
end
