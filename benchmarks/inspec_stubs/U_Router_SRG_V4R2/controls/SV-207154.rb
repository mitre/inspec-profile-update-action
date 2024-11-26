control 'SV-207154' do
  title 'The router must be configured to have Internet Control Message Protocol (ICMP) mask replies disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP Mask Reply messages out to any external interfaces.

If ICMP Mask Reply messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP mask replies on all external interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7415r382445_chk'
  tag severity: 'medium'
  tag gid: 'V-207154'
  tag rid: 'SV-207154r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000114'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7415r382446_fix'
  tag 'documentable'
  tag legacy: ['SV-92931', 'V-78225']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
