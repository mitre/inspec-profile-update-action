control 'SV-220512' do
  title 'The Cisco switch must be configured to off-load log records onto a different system than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

logging server 10.1.48.10 6

If the Cisco switch is not configured to off-load log records onto a different system than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to send log records to a syslog server as shown in the example below:

SW4(config)# logging server 10.1.48.10 6'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22227r539257_chk'
  tag severity: 'medium'
  tag gid: 'V-220512'
  tag rid: 'SV-220512r604141_rule'
  tag stig_id: 'CISC-ND-001310'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-22216r539258_fix'
  tag 'documentable'
  tag legacy: ['SV-110673', 'V-101569']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
