control 'SV-224197' do
  title 'The EDB Postgres Advanced Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "To ensure sufficient storage capacity for the audit logs, the DBMS must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the DBMS and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', 'Investigate whether there have been any incidents where the DBMS ran out of audit log space since the last time the space was allocated or other corrective measures were taken.

If there have been incidents, this is a finding.

To check how much storage capacity is available for audit records, first determine the location where the EDB audit logs are being written by executing the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW edb_audit_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS). 

Note that the default location for the EDB postgresql data directory is found in the directory where EDB Postgres Advanced Server is installed. The location of the data directory for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW data_directory"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If the default path is used for the postgresql data directory and the default setting of "edb_audit" is used for the edb_audit_directory parameter, the path to the EDB audit directory would be <EDB Postgres data directory>\\edb_audit. Depending on the version of EPAS installed, the options selected during installation, and the edb_audit_directory parameter setting, the path to the data directory and the EDB audit directory may be different.

With the EDB audit directory identified, note the disk on which this directory exists. Use the Windows Disk Management panel to determine how much space has been allocated to the disk and how much space remains. The Disk Management panel can be opened via "Start > Run > diskmgmt.msc". To determine the capacity, used, and free space on the disk via the Windows Explorer, right click to select the disk, and then select the "Properties" menu option. To determine how much space is currently being consumed by the audit log using Windows Explorer, right click select the audit directory and then select the "Properties" menu option.

If the remaining storage on the disk does not meet organizationally defined audit record storage requirements, this is a finding.'
  desc 'fix', %q(Allocate sufficient audit file space to the partition containing the EDB Audit directory to support peak demand.

Note that the EDB audit log directory is configured by the edb_audit_directory parameter. By default, the edb_audit_directory is set to "edb_audit", which results in an "edb_audit" directory being created under the EPAS cluster's data directory for audit logs if auditing is enabled.)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25870r495609_chk'
  tag severity: 'medium'
  tag gid: 'V-224197'
  tag rid: 'SV-224197r508023_rule'
  tag stig_id: 'EP11-00-007900'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-25858r495610_fix'
  tag 'documentable'
  tag legacy: ['V-100415', 'SV-109519']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
