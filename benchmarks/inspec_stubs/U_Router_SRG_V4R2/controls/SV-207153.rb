control 'SV-207153' do
  title 'The router must be configured to have Internet Control Message Protocol (ICMP) unreachable notifications disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP unreachable notifications out to any external interfaces.

If ICMP unreachable notifications are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP unreachable notifications on all external interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7414r382442_chk'
  tag severity: 'medium'
  tag gid: 'V-207153'
  tag rid: 'SV-207153r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000113'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7414r382443_fix'
  tag 'documentable'
  tag legacy: ['SV-92929', 'V-78223']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
