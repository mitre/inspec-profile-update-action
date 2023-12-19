control 'SV-216543' do
  title 'The Cisco router must be configured to off-load log records onto a different system than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

logging 10.1.12.7 vrf default severity info

If the Cisco router is not configured to off-load log records onto a different system than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Cisco router to send log records to a syslog server as shown in the example below.

RP/0/0/CPU0:R3(config)#logging 10.1.12.7 severity info'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17778r288315_chk'
  tag severity: 'medium'
  tag gid: 'V-216543'
  tag rid: 'SV-216543r531088_rule'
  tag stig_id: 'CISC-ND-001310'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-17775r288316_fix'
  tag 'documentable'
  tag legacy: ['SV-105615', 'V-96477']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
