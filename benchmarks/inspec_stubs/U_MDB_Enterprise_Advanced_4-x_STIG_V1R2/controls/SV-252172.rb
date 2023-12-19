control 'SV-252172' do
  title 'MongoDB must allocate audit record storage capacity in accordance with site audit record storage requirements.'
  desc "In order to ensure sufficient storage capacity for the audit logs, MongoDB must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of MongoDB and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on MongoDB's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', 'MongoDB relies on the underlying operating system to allocate storage capacity for audit logs and as such, does not enforce arbitrary file size limits on audit logs. 

System administrators should confirm that the recommended centralized system logging has been enabled (e.g., syslog on Linux systems) in the /etc/mongod.conf configuration file. 

For example, on a Linux-based system using syslog which is mirrored to an off-server centralized location, confirm that the MongoDB configuration file (default location: /etc/mongod.conf) contains a properly configured auditLog such as follows:

auditLog:
   destination: syslog

If the auditLog entry is missing, or the destination does not reflect the intended application location, this is a finding. 

Investigate whether there have been any incidents where MongoDB ran out of audit log space since the last time the space was allocated or other corrective measures were taken. 

If there have been incidents where MongoDB ran out of audit log space, this is a finding.'
  desc 'fix', 'If an auditLog has not been specified, or a centralized system log (which is recommended) has not been enabled, configure these in the mongod.conf configuration file:

auditLog:
   destination: syslog

See documentation for additional configuration: https://docs.mongodb.com/v4.4/tutorial/configure-auditing/

Allocate sufficient space to the storage volume hosting the file identified in the MongoDB configuration "auditLog.path" to support audit file peak demand.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55628r813896_chk'
  tag severity: 'medium'
  tag gid: 'V-252172'
  tag rid: 'SV-252172r855509_rule'
  tag stig_id: 'MD4X-00-004900'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-55578r813897_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
