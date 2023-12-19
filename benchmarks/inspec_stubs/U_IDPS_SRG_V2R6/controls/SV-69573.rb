control 'SV-69573' do
  title 'The IDPS must off-load log records to a centralized log server in real-time.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the IDPS is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real-time which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the IDPS off-loads log records to a centralized log server in real-time.

If the IDPS does not off-load log records to a centralized log server in real-time, this is a finding.'
  desc 'fix', 'Configure the IDPS to off-load log records to a centralized log server in real-time.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55327'
  tag rid: 'SV-69573r1_rule'
  tag stig_id: 'SRG-NET-000511-IDPS-00012'
  tag gtitle: 'SRG-NET-000511-IDPS-00012'
  tag fix_id: 'F-60193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
