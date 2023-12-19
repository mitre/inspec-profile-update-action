control 'SV-24592' do
  title 'Application objects should be owned by accounts authorized for ownership.'
  desc 'Database object ownership implies full privileges to the owned object including the privilege to assign access to the owned objects to other subjects. Unmanaged or uncontrolled ownership of objects can lead to unauthorized object grants and alterations.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):
  select distinct owner from dba_objects
  where owner not in 
  ('ANONYMOUS','AURORA$JIS$UTILITY$',
   'AURORA$ORB$UNAUTHENTICATED',
   'CTXSYS','DBSNMP','DIP','DVF','DVSYS', 
   'EXFSYS','LBACSYS','MDDATA',
   'MDSYS','MGMT_VIEW','ODM','ODM_MTR', 
   'OLAPSYS','ORDPLUGINS', 'ORDSYS', 
   'OSE$HTTP$ADMIN','OUTLN','PERFSTAT', 
   'PUBLIC','REPADMIN','RMAN','SI_INFORMTN_SCHEMA', 
   'SYS','SYSMAN','SYSTEM','TRACESVR',
   'TSMSYSWK_TEST','WKPROXY','WKSYS', 
   'WKUSER','WMSYS','XDB')
  and owner not in 
  (select grantee from dba_role_privs where granted_role='DBA');
 
If any records are returned, then confirm that any database object owner accounts listed are application owner accounts authorized by the IAO. If any are not, this is a Finding.  

NOTE:  Confirmed default Oracle accounts returned by the SQL statement above should be considered a false positive. See Oracle MetaLink Note 160861.1 for a current list of default accounts.

NOTE:  Some applications may be designed to require users to create temporary tables during application execution. This design is not considered good security practice and results in a Finding for unauthorized application object owners as application user accounts are not allowed to have system privileges assigned (CREATE TABLE, etc.) nor allowed to own objects in the database. One possible suggestion for resolving this issue is to have the application object owner create a static table for user temporary data storage. All users would share the same table."
  desc 'fix', 'Document all authorized application object owner accounts.

Use only authorized application object owner accounts to install and maintain application database objects.

Revoke privileges to create, drop, replace or alter application objects from unauthorized application object owners.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1094r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15607'
  tag rid: 'SV-24592r2_rule'
  tag stig_id: 'DG0008-ORACLE11'
  tag gtitle: 'DBMS application object ownership'
  tag fix_id: 'F-16157r1_fix'
  tag responsibility: 'Database Administrator'
end
