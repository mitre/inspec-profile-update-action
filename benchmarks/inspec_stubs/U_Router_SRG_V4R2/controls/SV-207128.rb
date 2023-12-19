control 'SV-207128' do
  title 'The PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', %q(Review the router configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS.

If storm control is not enabled for broadcast traffic, this is a finding.

Note: The threshold level can be from 0 to 100 percent of the link's bandwidth, where "0" suppresses all traffic. Most FastEthernet switching modules do not support multicast and unicast traffic storm control.)
  desc 'fix', 'Configure storm control for each VPLS bridge domain. Base the suppression threshold on expected traffic rates plus some additional capacity.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7389r382322_chk'
  tag severity: 'medium'
  tag gid: 'V-207128'
  tag rid: 'SV-207128r604135_rule'
  tag stig_id: 'SRG-NET-000193-RTR-000002'
  tag gtitle: 'SRG-NET-000193'
  tag fix_id: 'F-7389r382323_fix'
  tag 'documentable'
  tag legacy: ['V-78307', 'SV-93013']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
