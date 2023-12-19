control 'SV-88749' do
  title 'The Cisco IOS XE router must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to send logs to a syslog server.

The configuration should look similar to the example below:

logging host 1.1.1.1

If it is not configured to send logs to a syslog server, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to enable syslog.

The configuration should look similar to the example below:

logging host 1.1.1.1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74167r4_chk'
  tag severity: 'medium'
  tag gid: 'V-74075'
  tag rid: 'SV-88749r2_rule'
  tag stig_id: 'CISR-ND-000128'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-80615r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
