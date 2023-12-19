control 'SV-216747' do
  title 'The Cisco router must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the router configuration and verify that ipv4 mask-reply command is not enabled on any external interfaces as shown in the example below. 

interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 mask-reply 

If the router configuration has the ipv4 mask-reply command is enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ipv4 mask-reply on all external interfaces as shown below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1
RP/0/0/CPU0:R3(config-if)#no ipv4 mask-reply'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17979r288630_chk'
  tag severity: 'medium'
  tag gid: 'V-216747'
  tag rid: 'SV-216747r856438_rule'
  tag stig_id: 'CISC-RT-000180'
  tag gtitle: 'SRG-NET-000362-RTR-000114'
  tag fix_id: 'F-17977r288631_fix'
  tag 'documentable'
  tag legacy: ['SV-105839', 'V-96701']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
