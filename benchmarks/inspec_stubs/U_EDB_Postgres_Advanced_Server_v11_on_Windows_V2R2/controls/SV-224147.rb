control 'SV-224147' do
  title 'The EDB Postgres Advanced Server must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, action be taken to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, approved actions in response to an audit failure are as follows:

(i) If the failure was caused by the lack of audit record storage capacity, the DBMS must continue generating audit records, if possible (automatically restarting the audit service if necessary), and overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the DBMS must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations.'
  desc 'check', 'If the system documentation indicates audit trail completeness takes precedence over availability this is not applicable (NA).

If an externally managed and monitored partition or logical volume that can be grown dynamically is being used for logging, this is not a finding. 

If EDB Postgres Advanced Server (EPAS) is auditing to a directory that is not being actively checked for availability of disk space, and if a tool, utility, script, or other mechanism is not being used to ensure sufficient disk space is available for the creation of new audit logs, this is a finding.

If a tool, utility, script, or other mechanism is being used to rotate audit logs and oldest logs are not being removed to ensure sufficient space for newest logs or oldest logs are not being replaced by newest logs, this is a finding.'
  desc 'fix', %q(Establish a process with accompanying tools for monitoring available disk space and ensuring that sufficient disk space is maintained in order to continue generating audit logs, overwriting the oldest existing records if necessary.

If the organization does not employ an existing log management utility, the following example identifies one approach that may be followed to rotate EDB audit log files on Windows. 

Determine the maximum size of the audit log directory. For this example fix, assume the audit log directory must have a maximum size of 100MB. Divide the maximum size of the directory by 10 to determine the size of the log files for rotation. For this example, the audit log file size will be set to 10Mb. Perform the following steps to ensure that the audit log directory is never more than 90% full and the oldest logs are removed to make room for new logs:

1) Execute the following SQL statements to review current auditing related settings and to configure EPAS to generate a new audit log file when the current log file has reached the log file size determined above (10 Mb):

 -- List current EDB Audit settings
 SELECT name, setting FROM pg_settings WHERE category LIKE 'EnterpriseDB Audit%' ORDER BY name;

 /*
 * Note: If edb_audit is not set to 'csv' or 'xml', auditing is not enabled.
 * To enable EDB auditing, issue one of the following SQL statements:
 *
 * ALTER SYSTEM SET edb_audit TO 'xml';
 * 
 * or
 *
 * ALTER SYSTEM SET edb_audit TO 'csv';
 *
 */

 -- Set edb_audit_filename parameter to ensure unique name for each log file that is generated
 ALTER SYSTEM SET edb_audit_filename TO 'audit-%Y%m%d_%H%M%S';

 -- Set edb_audit_rotation_size to desired maximum file size (e.g., 10 Mb)
 ALTER SYSTEM SET edb_audit_rotation_size TO 10;

 -- Reload configuration settings to put the updated settings into effect
 SELECT pg_reload_conf();

 -- List current EDB Audit settings to confirm updates are in place
 SELECT name, setting FROM pg_settings WHERE category LIKE 'EnterpriseDB Audit%' ORDER BY name;

2) Using a text editor, create a Windows batch file with the following content:

 @ECHO OFF
 SETLOCAL
 SET "targetdir=<Path to edb_audit Directory>"
 SET /a retain=8

 FOR /f "skip=%retain%delims=" %%a IN (
 'dir /b /a-d /o-d "%targetdir%\audit-????????_??????.xml" '
 ) DO DEL "%targetdir%\%%a"

 GOTO :EOF

3) Replace "<Path to edb_audit Directory>" for "targetdir" variable in the batch file (3rd line) to correspond to the EDB audit log directory configured for your EPAS instance. Note that the EDB audit log directory is configured by the edb_audit_directory parameter. By default, the edb_audit_directory is set to "edb_audit", which results in an "edb_audit" directory being created under the EPAS cluster's data directory for audit logs if auditing is enabled. The location of the data directory for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW data_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If default setting of "edb_audit" is used for the edb_audit_directory parameter, the path to the EDB audit directory would be <EDB Postgres data directory>\edb_audit.

4) Update the "retain" variable in the batch file (4th line) to correspond to the desired minimum number of audit log files that should be retained in the directory. It should be set so that sufficient headroom is maintained in the directory for log files generated between runs of the batch file.

5) Save the batch file to a location that would be accessible to the Windows Task Scheduler. For this example, save the file to "C:\Windows\System32\Manage_EDB_Audit_Logs.bat".

6) Using the Windows Task Scheduler, create a scheduled task to execute the Manage_EDB_Audit_Logs.bat file on a periodic basis. At a minimum, it is recommended that the task be scheduled to perform this action at least on an hourly basis. Depending on the various audit log settings and database activity, it may be necessary to configure the task to be run more frequently.)
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25820r495461_chk'
  tag severity: 'high'
  tag gid: 'V-224147'
  tag rid: 'SV-224147r508023_rule'
  tag stig_id: 'EP11-00-002400'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag fix_id: 'F-25808r495462_fix'
  tag 'documentable'
  tag legacy: ['SV-109425', 'V-100321']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
