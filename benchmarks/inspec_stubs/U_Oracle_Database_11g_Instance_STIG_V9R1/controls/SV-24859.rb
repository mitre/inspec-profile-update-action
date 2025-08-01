control 'SV-24859' do
  title 'The audit table should be owned by SYS or SYSTEM.'
  desc 'Audit data is frequently targeted by malicious users as it can provide a means to detect their activity. The protection of the audit trail data is of special concern and requires restrictions to allow only the auditor and DBMS backup, recovery, and maintenance users access to it.'
  desc 'check', "From SQL*Plus:

  select owner from dba_tables where table_name = 'AUD$';

If the owner account returned is not SYS or SYSTEM, this is a Finding.

If the AUD$ tables does not exist, this is a Finding."
  desc 'fix', 'Change the owner of the $AUD table to SYS or SYSTEM account.

OR

Recreate the audit table while logged in as SYS or SYSTEM.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29418r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2515'
  tag rid: 'SV-24859r2_rule'
  tag stig_id: 'DO0190-ORACLE11'
  tag gtitle: 'Oracle audit table ownership'
  tag fix_id: 'F-26445r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
