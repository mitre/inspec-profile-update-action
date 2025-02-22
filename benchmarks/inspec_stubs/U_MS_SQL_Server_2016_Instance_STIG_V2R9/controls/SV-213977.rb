control 'SV-213977' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'SQL Server must prevent unauthorized and unintended information transfer via shared system resources. Permitting only SQL Server processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database log files, and database backup files. 

To obtain the location of SQL Server data, transaction log, and backup files, open and execute the supplemental file "Get SQL Data and Backup Directories.sql".

For each of the directories returned by the above script, verify whether the correct permissions have been applied.

1) Launch Windows Explorer.
2) Navigate to the folder.
3) Right-click the folder and click "Properties".
4) Navigate to the "Security" tab.
5) Review the listing of principals and permissions.

Account Type			Directory Type		Permission
-----------------------------------------------------------------------------------------------
Database Administrators      	ALL                   		Full Control
SQL Server Service SID       	Data; Log; Backup;    	Full Control
SQL Server Agent Service SID 	Backup                	Full Control
SYSTEM                       		ALL                   		Full Control
CREATOR OWNER                	ALL                   		Full Control

For information on how to determine a "Service SID", go to:
https://aka.ms/sql-service-sids

Additional permission requirements, including full directory permissions and operating system rights for SQL Server, are documented at:
https://aka.ms/sqlservicepermissions

If any additional permissions are granted but not documented as authorized, this is a finding.'
  desc 'fix', 'Remove any unauthorized permission grants from SQL Server data, log, and backup directories.

1) On the "Security" tab, highlight the user entry.
2) Click "Remove".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15194r313714_chk'
  tag severity: 'medium'
  tag gid: 'V-213977'
  tag rid: 'SV-213977r879649_rule'
  tag stig_id: 'SQL6-D0-010000'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-15192r313715_fix'
  tag 'documentable'
  tag legacy: ['SV-93921', 'V-79215']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
