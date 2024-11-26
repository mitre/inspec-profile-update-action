control 'SV-207199' do
  title 'The VPN Gateway must generate log records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the log records must also identify sources of events such as IP addresses, processes, and node or device names.'
  desc 'check', 'Verify the VPN Gateway  generates log records containing information to establish the source of the events.

If the VPN Gateway does not generate log records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate log records containing information to establish the source of the events.'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7459r378218_chk'
  tag severity: 'low'
  tag gid: 'V-207199'
  tag rid: 'SV-207199r608988_rule'
  tag stig_id: 'SRG-NET-000089-VPN-000330'
  tag gtitle: 'SRG-NET-000089'
  tag fix_id: 'F-7459r378219_fix'
  tag 'documentable'
  tag legacy: ['SV-106207', 'V-97069']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
