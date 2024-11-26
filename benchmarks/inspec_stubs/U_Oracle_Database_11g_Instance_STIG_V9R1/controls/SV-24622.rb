control 'SV-24622' do
  title 'Audit records should be restricted to authorized individuals.'
  desc 'Audit data is frequently targeted by malicious users as it can provide a means to detect their activity. The protection of the audit trail data is of special concern and requires restrictions to allow only the auditor and DBMS backup, recovery, and maintenance users access to it.'
  desc 'check', "From SQL*Plus:
  select value from v$parameter where name='audit_trail';

If none of the following values is displayed, this check is Not a Finding.

Oracle 11.1 – 11.2	= 'db'
Oracle 11.1 – 11.2	= 'db_extended'

Review access granted to the AUD$ table.

From SQL*Plus:
  select grantee from dba_tab_privs
  where table_name = 'AUD$' 
  and grantee not in ('DELETE_CATALOG_ROLE')
  and grantee not in 
  (select grantee from dba_role_privs
   where granted_role = 'DBA')
  order by grantee;

View access granted to the AUD$ table against those authorized in the System Security Plan.

If any are not authorized, this is a Finding."
  desc 'fix', 'Document and authorize accounts granted access to the AUD$ table in the System Security Plan.

Revoke access permissions granted to the AUD$ table from unauthorized users.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-26277r2_chk'
  tag severity: 'medium'
  tag gid: 'V-5686'
  tag rid: 'SV-24622r2_rule'
  tag stig_id: 'DG0032-ORACLE11'
  tag gtitle: 'DBMS audit record access'
  tag fix_id: 'F-2559r1_fix'
  tag responsibility: 'Database Administrator'
end
