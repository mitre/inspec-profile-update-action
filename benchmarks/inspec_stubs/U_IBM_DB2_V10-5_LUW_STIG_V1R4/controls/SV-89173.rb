control 'SV-89173' do
  title 'In the event of a system failure, DB2 must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is normally a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Review the system backup and recovery plan for db2 database to determine whether the database is in archive logging or circular logging, the recovery methods to be used, the backup schedule, backup media integration and the plan for testing database restoration. If any information is absent, this is a finding.

Run the following command to get the details on the logging method:

     $db2 get db cfg

If roll forward recovery is required and both logarchmeth1 and logarchmeth2 are set to value OFF then DB2 is not in archive logging, this is a finding.

Run the following command to verify backup history:

     $db2 list history backup all for <dbname>

Review the output of the above to see frequency and mode of backups, If the database is not being backed up per the organization’s system backup plan, this is a finding. 

Review evidence that database recovery is tested annually or more often per the backup and recovery document, and that the most recent test was successful. If not, this is a finding.'
  desc 'fix', 'Modify the database backup plan to include whether the database needs to be in archive logging, the correct recovery model to be used, the backup schedule, and the plan for testing the database restoration.

Update db2 logging to archive logging for the database which requires roll forward recovery using the following db2 command:

     $db2 update db2 cfg for <database name> using LOGARCHMETH1 <value>

Note: Set the value as per your online file system or backup vendor like TSM 

Verify and correct the scheduled backup jobs.

Correct any issues that have been causing backups to fail.

Test the restoration of the database at least once a year; correct any issues that cause it to fail. Maintain a record of these tests.

Note: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.1.0/com.ibm.db2.luw.admin.config.doc/doc/r0011448.html
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.cmd.doc/doc/r0001991.html'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74425r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74499'
  tag rid: 'SV-89173r1_rule'
  tag stig_id: 'DB2X-00-005300'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-81099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
