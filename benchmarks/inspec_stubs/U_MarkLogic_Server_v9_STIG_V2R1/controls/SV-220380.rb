control 'SV-220380' do
  title 'MarkLogic Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "To ensure sufficient storage capacity for the audit logs, the DBMS must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the DBMS and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', 'Investigate whether there have been any incidents where the MarkLogic server ran out of audit log space since the last time the space was allocated or other corrective measures were taken.

If there have been, this is a finding.'
  desc 'fix', 'All MarkLogic logs, including audits, are stored within the Data directory (i.e., /var/opt/MarkLogic/Logs). 

MarkLogic requires the lesser of 2x the content forest size, or 96GB of free space. 

System Administrators must ensure/configure between 1.5 and 3x free disk space for normal operations.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22095r401591_chk'
  tag severity: 'medium'
  tag gid: 'V-220380'
  tag rid: 'SV-220380r855485_rule'
  tag stig_id: 'ML09-00-007200'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-22084r855484_fix'
  tag 'documentable'
  tag legacy: ['SV-110109', 'V-101005']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
