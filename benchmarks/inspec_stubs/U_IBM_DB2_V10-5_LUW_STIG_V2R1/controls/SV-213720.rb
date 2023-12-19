control 'SV-213720' do
  title 'DB2 must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "In order to ensure sufficient storage capacity for the audit logs, the DBMS must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the DBMS and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', 'Run the following command to find the location of the audit data directory: 

     $db2audit describe 

Note the location of audit data directory.

Check the operating system log records find out if there has been any out of space event for that location.

If there has been any out of space event for audit data directory, this is a finding.

Take samples of peak database activity and measure the space utilized in the audit data directory location during that time.

If the audit data directory is not sized to handle the workload between audit archiving intervals this is a finding.'
  desc 'fix', 'Allocate space to the file system where the audit data directory resides.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14941r295209_chk'
  tag severity: 'medium'
  tag gid: 'V-213720'
  tag rid: 'SV-213720r879730_rule'
  tag stig_id: 'DB2X-00-007500'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-14939r295210_fix'
  tag 'documentable'
  tag legacy: ['SV-89243', 'V-74569']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
