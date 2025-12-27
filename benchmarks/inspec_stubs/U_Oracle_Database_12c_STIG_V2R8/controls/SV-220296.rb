control 'SV-220296' do
  title 'The DBMS must preserve any organization-defined system state information in the event of a system failure.'
  desc 'Failure in a known state can address safety or security in accordance with the mission/business needs of the organization. Failure in a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes.'
  desc 'check', 'If the database is used solely for transient data (such as one dedicated to Extract-Transform-Load (ETL)), and a clear plan exists for the recovery of the database by means other than archiving, this is not a finding.

If it has been determined that up-to-the second recovery is not necessary and this fact is recorded in the system documentation, with appropriate approval, this is not a finding.

Check DBMS settings to determine whether system state information is being preserved in the event of a system failure.

The necessary state information is defined as "information necessary to determine cause of failure and to return to operations with least disruption to mission/business processes".

Oracle creates what is known as archive logs. Archive logs contain information required to replay a transaction should something happen. The redo logs are also used to copy transactions or pieces of transactions.

Issue the following commands to check the status of archive log mode:

$ sqlplus connect as sysdba --Check current archivelog mode in database

SQL> archive log list
Database log mode Archive Mode
Automatic archival Enabled
Archive destination /home/oracle/app/oracle/arc2/ORCL
Oldest online log sequence 433
Next log sequence to archive 435
Current log sequence 435

If archive log mode is not enabled, this is a finding.'
  desc 'fix', 'Configure DBMS settings to preserve all required system state information in the event of a system failure. 

If the database is not in archive log mode, issue the following commands to put the database in archive log mode. The database must be normally shutdown and restarted before it can be placed in archive log mode. 

$ sqlplus connect as sysdba -- stop and dismount database and shutdown instance.
SQL> shutdown immediate;

Database closed.
Database dismounted.
ORACLE instance shut down.

SQL> startup mount; -- Restart instance.

ORACLE instance started.
Total System Global Area 1653518336 bytes
Fixed Size 2228904 bytes
Variable Size 1325403480 bytes
Database Buffers 318767104 bytes
Redo Buffers 7118848 bytes
Database mounted.

SQL> alter database archivelog; -- Enable ArchiveLog
Database altered.

SQL> alter database open; -- Re-open database
Database altered.

Issue the following command to see the new status:
SQL> select log_mode from v$database;

LOG_MODE
------------
ARCHIVELOG

SQL> archive log list;

Database log mode Archive Mode
Automatic archival Enabled
Archive destination USE_DB_RECOVERY_FILE_DEST
Oldest online log sequence 294
Next log sequence to archive 296
Current log sequence 296

The database is now in archive log mode, and transactions are either being recorded to transport to another database or being re-applied if the database becomes corrupt and needs to be restored from the last backup. Use the redo logs to replay transactions not captured in the backup.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22011r392019_chk'
  tag severity: 'medium'
  tag gid: 'V-220296'
  tag rid: 'SV-220296r879641_rule'
  tag stig_id: 'O121-C2-018200'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-22003r392020_fix'
  tag 'documentable'
  tag legacy: ['SV-76259', 'V-61769']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
