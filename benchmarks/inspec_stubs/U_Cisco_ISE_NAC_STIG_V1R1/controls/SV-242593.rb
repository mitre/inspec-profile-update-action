control 'SV-242593' do
  title 'The Cisco ISE must off-load log records onto a different system.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Navigate to Administration >> System >> Backup and Restore.

Ensure that operational data backups are scheduled.

If operational backups are not scheduled, this is a finding.'
  desc 'fix', 'From the Web Admin portal:
1. Navigate to Administration >> System >> Backup and Restore.
2. Select the "Schedule" option next to Operational Data Backup.
3. Configure operational data backup at a desired frequency.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45868r714087_chk'
  tag severity: 'medium'
  tag gid: 'V-242593'
  tag rid: 'SV-242593r714089_rule'
  tag stig_id: 'CSCO-NC-000190'
  tag gtitle: 'SRG-NET-000334-NAC-001350'
  tag fix_id: 'F-45825r714088_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
