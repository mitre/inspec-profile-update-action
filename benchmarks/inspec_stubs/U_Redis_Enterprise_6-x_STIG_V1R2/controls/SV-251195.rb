control 'SV-251195' do
  title 'Redis Enterprise DBMS must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "To ensure sufficient storage capacity for the audit logs, the DBMS must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be offloaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the offloading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the DBMS and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are offloaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by offloaded records."
  desc 'check', 'Review organization documentation to determine the organization-defined audit record storage requirements. By default, Redis Enterprise will use whatever disk space is allocated for audit logs. It is the responsibility of the organization to ensure that the RHEL OS server hosting the service has been allocated enough storage space to avoid running out of log space.

Interview the system administrator and review audit log configuration and alerts to investigate whether there have been any incidents where the Redis Enterprise server ran out of audit log space since the last time the space was allocated, or other corrective measures were taken. 

If such incidents have occurred, this is a finding.

Review the Redis Enterprise control pane as an admin user. 

If alerts are present indicating that storage is full or is at 95 percent full, this is a finding.'
  desc 'fix', 'Ensure that the server is configured with enough storage space to accommodate database and audit record storage. The right amount of storage will be dependent on a variety of factors such as: number of databases, database size, HA enabled, persistence enabled, etc.

At no time should storage be more than 95 percent full.

See the following documents for hardware requirements:
https://docs.redislabs.com/latest/rs/administering/designing-production/hardware-requirements/
and
https://docs.redislabs.com/latest/rs/installing-upgrading/file-locations/'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54630r855600_chk'
  tag severity: 'medium'
  tag gid: 'V-251195'
  tag rid: 'SV-251195r855602_rule'
  tag stig_id: 'RD6X-00-005500'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-54584r855601_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
