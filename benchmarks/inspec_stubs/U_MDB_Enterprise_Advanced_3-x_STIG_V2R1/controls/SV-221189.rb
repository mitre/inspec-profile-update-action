control 'SV-221189' do
  title 'MongoDB must allocate audit record storage capacity in accordance with site audit record storage requirements.'
  desc "In order to ensure sufficient storage capacity for the audit logs, MongoDB must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of MongoDB and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on MongoDB's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', 'Investigate whether there have been any incidents where MongoDB ran out of audit log space since the last time the space was allocated or other corrective measures were taken.  

If there have been incidents where MongoDB ran out of audit log space, this is a finding.

A MongoDB audit log that is configured to be stored in a file is identified in the MongoDB configuration file (default: /etc/mongod.conf) under the "auditLog:" key and subkey "destination:" where "destination" is "file".  

If this is the case then the "AuditLog:" subkey "path:" determines where (device/directory) that file will be located.  

View the mongodb configuration file (default location: /etc/mongod.conf) and identify how the "auditlog.destination" is configured.

When the "auditlog.destination" is "file", this is a finding.'
  desc 'fix', 'View the mongodb configuration file (default location: /etc/mongod.conf) and view the "auditlog.path" to identify the storage volume.

Allocate sufficient space to the storage volume hosting the file identified in the MongoDB configuration "auditLog.path" to support audit file peak demand.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22904r411061_chk'
  tag severity: 'medium'
  tag gid: 'V-221189'
  tag rid: 'SV-221189r411063_rule'
  tag stig_id: 'MD3X-00-000620'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-22893r411062_fix'
  tag 'documentable'
  tag legacy: ['SV-96619', 'V-81905']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
