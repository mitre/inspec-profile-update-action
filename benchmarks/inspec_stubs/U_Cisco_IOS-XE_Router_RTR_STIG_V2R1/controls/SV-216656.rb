control 'SV-216656' do
  title 'The Cisco router must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the router configuration and verify that ip mask-reply command is not enabled on any external interfaces as shown in the example below: 

interface GigabitEthernet0/1
 ip address x.x.x.x 255.255.255.0
 ip mask-reply

If the ip mask-reply command is configured on any external interface, this is a finding.'
  desc 'fix', 'Disable ip mask-reply on all external interfaces as shown below:

R4(config)#int g0/1
R4(config-if)#no ip mask-reply'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17889r287925_chk'
  tag severity: 'medium'
  tag gid: 'V-216656'
  tag rid: 'SV-216656r531086_rule'
  tag stig_id: 'CISC-RT-000180'
  tag gtitle: 'SRG-NET-000362-RTR-000114'
  tag fix_id: 'F-17887r287926_fix'
  tag 'documentable'
  tag legacy: ['V-96885', 'SV-106023']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
