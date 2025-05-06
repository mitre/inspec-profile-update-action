control 'SV-81867' do
  title 'In the event of a system failure, SQL Server must preserve any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. The existence and reliability of database backups is an essential aspect of the ability to fail to a known state. It helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

Backups must be performed according to an appropriate schedule, and must be tested periodically to provide assurance that they can be used for restoring the database.'
  desc 'check', 'Review the system security plan (SSP) to determine whether the database is static, the recovery model to be used, the backup schedule, and the plan for testing database restoration.  If the SSP does not state that the database is static, assume that it is not static.  If any of the other information is absent, this is a finding.

If the database is not static, but the documented recovery model is Simple, this is a finding.

If the database is not static, and the documented recovery model is Bulk Logged, but the justification and authorization for this are not documented, this is a finding.

In SQL Server Management Studio, Object Explorer, right-click on the name of the database; select Properties.  Select the Options page.

Observe the Recovery Model field, near the top of the page.  If this does not match the documented recovery model, this is a finding.

In Object Explorer, expand  <server name>  >>  SQL Server Agent  >>  Jobs.

Review the jobs set up to implement the backup plan.  If they are absent, this is a finding.

Right-click on each backup job; select View History.  If the history indicates a pattern of job failures, this is a finding.

Review evidence that database recovery is tested annually or more often, and that the most recent test was successful.  If not, this is a finding.'
  desc 'fix', 'Modify the system security plan, to include whether the database is static, the correct recovery model to be used, the backup schedule, and the plan for testing database restoration.

In SQL Server Management Studio, Object Explorer, right-click on the name of the database; select Properties.  Select the Options page.  Set the Recovery Model field, near the top of the page, to the correct value.

In Object Explorer, expand  <server name>  >>  SQL Server Agent  >>  Jobs.  Create, modify and delete jobs to implement the backup schedule.   (Alternatively, this may done using T-SQL code.)

Correct any issues that have been causing backups to fail.

Test the restoration of the database at least once a year; correct any issues that cause it to fail.  Maintain a record of these tests.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67377'
  tag rid: 'SV-81867r2_rule'
  tag stig_id: 'SQL4-00-021210'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-73489r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
