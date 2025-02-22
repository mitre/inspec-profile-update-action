control 'SV-251199' do
  title 'Redis Enterprise DBMS must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'Redis Enterprise can be configured to generate alerts for certain other key events, but not in the instance of an audit failure. The DBMS would depend on the base Linux OS to detect and shut down in the event of an audit processing failure.

It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When the need for system availability does not outweigh the need for a complete audit trail, the DBMS should shut down immediately, rolling back all in-flight transactions.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If the application owner has determined that the need for system availability outweighs the need for a complete audit trail, this is not applicable. 

Otherwise, review the procedures, manual and/or automated, for monitoring the space used by audit trail(s) and for offloading audit records to a centralized log management system.

If the procedures do not exist, this is a finding.

If the procedures exist, request evidence that they are followed. If the evidence indicates that the procedures are not followed, this is a finding.

If the procedures exist, inquire if the system has ever run out of audit trail space in the last two years or since the last system upgrade, whichever is more recent. If it has run out of space in this period, and the procedures have not been updated to compensate, this is a finding.'
  desc 'fix', 'Modify DBMS, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54634r804785_chk'
  tag severity: 'medium'
  tag gid: 'V-251199'
  tag rid: 'SV-251199r804787_rule'
  tag stig_id: 'RD6X-00-005900'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-54588r804786_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
