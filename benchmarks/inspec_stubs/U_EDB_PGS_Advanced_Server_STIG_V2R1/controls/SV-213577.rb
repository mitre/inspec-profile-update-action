control 'SV-213577' do
  title 'The EDB Postgres Advanced Server must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When the need for system availability does not outweigh the need for a complete audit trail, the DBMS should shut down immediately, rolling back all in-flight transactions.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If Postgres Enterprise Manager (PEM) is not installed and configured to shut down the database when the audit log is full, this is a finding.'
  desc 'fix', 'Install PEM and configure an alert to shut down the PPAS server when the audit log mount point is at 99 percent full. Refer to the Supplemental Procedures document, supplied with this STIG, for guidance on configuring alerts.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14799r290043_chk'
  tag severity: 'medium'
  tag gid: 'V-213577'
  tag rid: 'SV-213577r508024_rule'
  tag stig_id: 'PPS9-00-002300'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-14797r290044_fix'
  tag 'documentable'
  tag legacy: ['SV-83513', 'V-68909']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
