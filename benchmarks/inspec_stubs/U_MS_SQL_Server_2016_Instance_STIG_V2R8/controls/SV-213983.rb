control 'SV-213983' do
  title 'SQL Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "In order to ensure sufficient storage capacity for the audit logs, SQL Server must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism. 
 
The task of allocating audit record storage capacity is usually performed during initial installation of SQL Server and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both. 
 
In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on SQL Server's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', 'If the database is setup to write audit logs using APPLICATION or SECURITY event logs rather than writing to a file, this is N/A.

Check the server documentation for the SQL Audit file size configurations. Locate the Audit file path and drive. 
 
SELECT max_file_size, max_rollover_files, log_file_path AS "Audit Path"  
FROM sys.server_file_audits 
 
Calculate the space needed as the maximum file size and number of files from the SQL Audit File properties. 
 
If the calculated product of the "max_file_size" times the "max_rollover_files" exceeds the size of the storage location or if "max_file_size" or "max_rollover_files" are set to "0" (UNLIMITED), this is a finding.'
  desc 'fix', 'Review the SQL Audit file location; ensure the destination has enough space available to accommodate the maximum total size of all files that could be written. 
 
Configure the maximum number of audit log files that are to be generated, staying within the number of logs the system was sized to support. 
 
Update the "max_files" parameter of the audits to ensure the correct number of files is defined.

If writing to application event logs or security logs, space considerations are covered in the Windows Server STIGs. Be sure to reference these depending on the OS in use.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15200r799962_chk'
  tag severity: 'medium'
  tag gid: 'V-213983'
  tag rid: 'SV-213983r855967_rule'
  tag stig_id: 'SQL6-D0-010900'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-15198r799963_fix'
  tag 'documentable'
  tag legacy: ['SV-93933', 'V-79227']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
