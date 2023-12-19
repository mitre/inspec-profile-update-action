control 'SV-219701' do
  title 'Execute permission must be revoked from PUBLIC for restricted Oracle packages.'
  desc 'Access to the following packages should be restricted to authorized accounts only.

UTL_FILE: allows Oracle accounts to read and write files on the host operating system.
UTL_SMTP: allows messages to be sent from an arbitrary user.
UTL_TCP: allows arbitrary data to be sent from the database server.
UTL_HTTP: allows the database server to send and receive data via HTTP.
DBMS_RANDOM: allows encrypting of data without requiring safe management of encryption keys.
DBMS_LOB: allows users access to files stored outside the database.
DBMS_SQL: allows users to write dynamic SQL procedures.
DBMS_SYS_SQL: allows users to execute SQL with DBA privileges.
DBMS_JOB: allows users to submit jobs to the database job queue.
DBMS_BACKUP_RESTORE:  allows users to backup and restore database data.
DBMS_OBFUSCATION_TOOLKIT:  allows users access to encryption and decryption functions.'
  desc 'check', "From SQL*Plus:
select table_name from dba_tab_privs
where grantee='PUBLIC' 
and privilege ='EXECUTE'
and table_name in
('UTL_FILE', 'UTL_SMTP', 'UTL_TCP', 'UTL_HTTP',
'DBMS_RANDOM', 'DBMS_LOB', 'DBMS_SQL',
'DBMS_SYS_SQL', 'DBMS_JOB',
'DBMS_BACKUP_RESTORE',
'DBMS_OBFUSCATION_TOOLKIT');

If any records are returned, this is a Finding."
  desc 'fix', 'Revoking all default installation privilege assignments from PUBLIC is not required at this time. However, execute permissions to the specified packages is required to be revoked from PUBLIC. Removal of these privileges from PUBLIC may result in invalid packages in version 10.1 and later of Oracle and an inability to execute default Oracle applications and utilities. 

To correct this problem, grant execute privileges on these packages directly to the SYSMAN, WKSYS, MDSYS and SYSTEM accounts as well as any other default Oracle database and custom application object owner accounts as necessary to support execution of applications/utilities installed with an Oracle Database Server.

At a minimum, revoke the following:

From SQL*Plus:
revoke execute on UTL_FILE from PUBLIC;
revoke execute on UTL_SMTP from PUBLIC;
revoke execute on UTL_TCP from PUBLIC;
revoke execute on UTL_HTTP from PUBLIC;
revoke execute on DBMS_RANDOM from PUBLIC;
revoke execute on DBMS_LOB from PUBLIC;
revoke execute on DBMS_SQL from PUBLIC;
revoke execute on DBMS_SYS_SQL from PUBLIC;
revoke execute on DBMS_JOB from PUBLIC;
revoke execute on DBMS_BACKUP_RESTORE from PUBLIC;
revoke execute on DBMS_OBFUSCATION_TOOLKIT from PUBLIC;'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21426r306952_chk'
  tag severity: 'medium'
  tag gid: 'V-219701'
  tag rid: 'SV-219701r401224_rule'
  tag stig_id: 'O112-BP-021800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21425r306953_fix'
  tag 'documentable'
  tag legacy: ['SV-68213', 'V-53973']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
