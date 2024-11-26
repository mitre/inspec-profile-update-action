control 'SV-239946' do
  title 'The Cisco ASA must be configured to generate log records containing information to establish when the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

VPN gateways often have a separate audit log for capturing VPN status and other information about the traffic (as opposed to the log capturing administrative and configuration actions).

Associating event types with detected events in the network audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.'
  desc 'check', 'Verify that the logging timestamp command has been configured as shown below.

logging enable
logging timestamp

If the ASA is not configured to generate traffic log entries containing information to establish when the events occurred, this is a finding.'
  desc 'fix', 'Configure the ASA to generate traffic log entries containing information to establish when the events occurred.

ASA(config)# logging timestamp'
  impact 0.3
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43179r666242_chk'
  tag severity: 'low'
  tag gid: 'V-239946'
  tag rid: 'SV-239946r666244_rule'
  tag stig_id: 'CASA-VN-000020'
  tag gtitle: 'SRG-NET-000078-VPN-000290'
  tag fix_id: 'F-43138r666243_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
