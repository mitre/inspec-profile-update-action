control 'SV-207198' do
  title 'The VPN Gateway must generate log records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as VPN gateway components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.'
  desc 'check', 'Verify the VPN Gateway generates  log records containing information to establish where the events occurred.

If the VPN Gateway does not generate log records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generates log records containing information to establish where the events occurred.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7458r378215_chk'
  tag severity: 'medium'
  tag gid: 'V-207198'
  tag rid: 'SV-207198r608988_rule'
  tag stig_id: 'SRG-NET-000088-VPN-000310'
  tag gtitle: 'SRG-NET-000088'
  tag fix_id: 'F-7458r378216_fix'
  tag 'documentable'
  tag legacy: ['SV-106205', 'V-97067']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
