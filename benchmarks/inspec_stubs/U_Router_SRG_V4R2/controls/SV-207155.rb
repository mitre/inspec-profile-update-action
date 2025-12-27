control 'SV-207155' do
  title 'The router must be configured to have Internet Control Message Protocol (ICMP) redirects disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP Redirect messages out to any external interfaces.

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP redirects on all external interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7416r382448_chk'
  tag severity: 'medium'
  tag gid: 'V-207155'
  tag rid: 'SV-207155r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000115'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7416r382449_fix'
  tag 'documentable'
  tag legacy: ['SV-92933', 'V-78227']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
