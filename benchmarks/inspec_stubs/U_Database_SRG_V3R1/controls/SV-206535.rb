control 'SV-206535' do
  title 'The DBMS must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When the need for system availability does not outweigh the need for a complete audit trail, the DBMS should shut down immediately, rolling back all in-flight transactions.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If the application owner has determined that the need for system availability outweighs the need for a complete audit trail, this is not applicable (NA). 

Review DBMS, OS, or third-party logging application settings and/or documentation to determine whether the system is capable of shutting down, rolling back all in-flight transactions, in the case of an auditing failure. If it is not, this is a finding.

If the system is capable of shutting down upon audit failure but is not configured to do so, this is a finding.'
  desc 'fix', 'Configure the system to shut down, rolling back all in-flight transactions, in the case of an auditing failure.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6795r291273_chk'
  tag severity: 'medium'
  tag gid: 'V-206535'
  tag rid: 'SV-206535r617447_rule'
  tag stig_id: 'SRG-APP-000109-DB-000049'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-6795r291274_fix'
  tag 'documentable'
  tag legacy: ['SV-42720', 'V-32383']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
