control 'SV-239939' do
  title 'The Cisco ASA must be configured to offload audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement as shown in the example below.

logging trap notifications
logging host NDM_INTERFACE 10.1.48.10 6/1514

Note: A logging list can be used as an alternative to the severity level.

If the Cisco ASA is not configured to offload log records onto a different system than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to send log records to a syslog server as shown in the example below.

ASA(config)# logging host NDM_INTERFACE 10.1.48.10 6/1514
ASA(config)# logging trap notifications 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43172r666178_chk'
  tag severity: 'medium'
  tag gid: 'V-239939'
  tag rid: 'SV-239939r666180_rule'
  tag stig_id: 'CASA-ND-001260'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-43131r666179_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
