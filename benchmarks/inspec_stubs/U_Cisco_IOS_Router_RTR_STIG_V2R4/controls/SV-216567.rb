control 'SV-216567' do
  title 'The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the router configuration to verify that the no ip redirects command has been configured on all external interfaces as shown in the example below.

interface GigabitEthernet0/1
 ip address x.x.x.x 255.255.255.0
 no ip redirects

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP redirects on all external interfaces as shown in the example below.

R4(config)#int g0/1
R4(config-if)#no ip redirects'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17802r287085_chk'
  tag severity: 'medium'
  tag gid: 'V-216567'
  tag rid: 'SV-216567r856186_rule'
  tag stig_id: 'CISC-RT-000190'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-17798r287086_fix'
  tag 'documentable'
  tag legacy: ['SV-105673', 'V-96535']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
