control 'SV-207196' do
  title 'The VPN Gateway must generate log records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

VPN gateways often have a separate audit log for capturing VPN status and other information about the traffic (as opposed to the log capturing administrative and configuration actions).

Associating event types with detected events in the network audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.'
  desc 'check', 'Configure the VPN Gateway generates log records containing information to establish when (date and time) the events occurred.

If the VPN Gateway does not generate log records containing information to establish when (date and time) the events occurred, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate log records containing information to establish when (date and time) the events occurred.'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7456r378209_chk'
  tag severity: 'low'
  tag gid: 'V-207196'
  tag rid: 'SV-207196r608988_rule'
  tag stig_id: 'SRG-NET-000078-VPN-000290'
  tag gtitle: 'SRG-NET-000078'
  tag fix_id: 'F-7456r378210_fix'
  tag 'documentable'
  tag legacy: ['SV-106201', 'V-97063']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
