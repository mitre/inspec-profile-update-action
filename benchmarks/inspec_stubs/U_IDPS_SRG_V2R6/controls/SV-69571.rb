control 'SV-69571' do
  title 'The IDPS must off-load log records to a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

This also prevents the log records from being lost if the logs stored locally are accidentally or intentionally deleted, altered, or corrupted.'
  desc 'check', 'Verify the IDPS off-loads log records to a centralized log server.

If the IDPS does not off-load log records to a centralized log server, this is a finding.'
  desc 'fix', 'Configure the IDPS to off-load log records to a centralized log server.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55325'
  tag rid: 'SV-69571r1_rule'
  tag stig_id: 'SRG-NET-000334-IDPS-00191'
  tag gtitle: 'SRG-NET-000334-IDPS-00191'
  tag fix_id: 'F-60191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
