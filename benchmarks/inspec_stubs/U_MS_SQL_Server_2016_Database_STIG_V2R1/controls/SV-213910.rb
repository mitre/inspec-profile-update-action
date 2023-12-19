control 'SV-213910' do
  title 'In the event of a system failure, hardware loss or disk failure, SQL Server must be able to restore necessary databases with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. In the event of a system failure, SQL Server must be able to bring the database back to a consistent state.'
  desc 'check', "Review the system security plan (SSP) to determine whether the database is static, the recovery model to be used, the backup schedule, and the plan for testing database restoration.

If the SSP does not state that the database is static, assume that it is not static. If any of the other information is absent, this is a finding. 

If the database is not static, and the documented recovery model is Bulk Logged, but the justification and authorization for this are not documented, this is a finding. 

Run the following to determine Recovery Model:

USE [master]
GO

SELECT name, recovery_model_desc
FROM sys.databases
ORDER BY name

If the recovery model description does not match the documented recovery model, this is a finding. 

Review the jobs set up to implement the backup plan. If they are absent, this is a finding. 

Check the history of the backups by running the following query.  It checks the last 30 days of backups by database.
USE [msdb]
GO

SELECT database_name, 
   CASE type
    WHEN 'D' THEN 'Full'
    WHEN 'I' THEN 'Differential'
    WHEN 'L' THEN 'Log'
   ELSE type
   END AS backup_type,
 is_copy_only,
 backup_start_date, backup_finish_date
FROM dbo.backupset
WHERE backup_start_date >= dateadd(day, - 30, getdate()) 
ORDER BY database_name, backup_start_date DESC

If the history indicates a pattern of job failures by missing or gaps in backups, this is a finding. 

Review evidence that database recovery is tested annually or more often, and that the most recent test was successful. If not, this is a finding."
  desc 'fix', 'Modify the system security plan, to include whether the database is static, the correct recovery model to be used, the backup schedule, and the plan for testing database restoration. 

In SQL Server Management Studio, Object Explorer, right-click on the name of the database; select Properties. Select the Options page. Set the Recovery Model field, near the top of the page, to the correct value. 

In Object Explorer, expand >> SQL Server Agent >> Jobs. Create, modify, and delete jobs to implement the backup schedule. (Alternatively, this may done using T-SQL code or Third-party Backup software.) 

Correct any issues that have been causing backups to fail. 

Test the restoration of the database at least once a year; correct any issues that cause it to fail. Maintain a record of these tests.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15128r313162_chk'
  tag severity: 'medium'
  tag gid: 'V-213910'
  tag rid: 'SV-213910r508025_rule'
  tag stig_id: 'SQL6-D0-001500'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-15126r313163_fix'
  tag 'documentable'
  tag legacy: ['V-79083', 'SV-93789']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
