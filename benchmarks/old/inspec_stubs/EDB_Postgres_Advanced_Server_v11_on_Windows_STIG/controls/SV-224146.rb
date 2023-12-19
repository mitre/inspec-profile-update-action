control 'SV-224146' do
  title 'The EDB Postgres Advanced Server must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, action be taken to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When the need for system availability does not outweigh the need for a complete audit trail, the DBMS should shut down immediately, rolling back all in-flight transactions.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If Postgres Enterprise Manager (PEM) is installed and configured to shut down the database when the audit log is full, this is not a finding.

Otherwise, review the procedures, manual and/or automated, for monitoring the space used by audit trail(s) and for off-loading audit records to a centralized log management system.

If the procedures do not exist, this is a finding.

If the procedures exist, request evidence that they are followed. If the evidence indicates that the procedures are not followed, this is a finding.

If the procedures exist, inquire if the system has ever run out of audit trail space in the last two years or since the last system upgrade, whichever is more recent. If it has run out of space in this period, and the procedures have not been updated to compensate, this is a finding.'
  desc 'fix', 'Modify DBMS, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.

If EDB Postgres Enterprise Manager (PEM) is in use, it may be configured to issue an alert, send an email to designated personnel, and shut down the EDB Postgres Advanced Server instance when the audit log mount point is at 99 percent full. Refer to the Supplemental Procedures document, supplied with this STIG, for guidance on configuring PEM alerts.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25819r495458_chk'
  tag severity: 'medium'
  tag gid: 'V-224146'
  tag rid: 'SV-224146r508023_rule'
  tag stig_id: 'EP11-00-002300'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-25807r495459_fix'
  tag 'documentable'
  tag legacy: ['SV-109423', 'V-100319']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
