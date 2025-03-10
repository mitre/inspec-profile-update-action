control 'SV-239856' do
  title 'The Cisco ASA must be configured to generate traffic log entries containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis of network traffic patterns, it is essential for security personnel to know when flow control events occurred (date and time) within the infrastructure.

Associating event types with detected events in the network traffic logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', 'Verify that the logging timestamp command has been configured as shown below.

logging enable
logging timestamp

If the ASA is not configured to generate traffic log entries containing information to establish when the events occurred, this is a finding.'
  desc 'fix', 'Configure the ASA to generate traffic log entries containing information to establish when the events occurred.

ASA(config)# logging timestamp'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43089r665852_chk'
  tag severity: 'medium'
  tag gid: 'V-239856'
  tag rid: 'SV-239856r665854_rule'
  tag stig_id: 'CASA-FW-000050'
  tag gtitle: 'SRG-NET-000075-FW-000010'
  tag fix_id: 'F-43048r665853_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
