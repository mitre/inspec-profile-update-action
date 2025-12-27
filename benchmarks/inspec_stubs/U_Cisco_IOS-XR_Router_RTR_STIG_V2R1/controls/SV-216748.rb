control 'SV-216748' do
  title 'The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the router configuration to verify that ipv4 redirects command has not been configured on any external interface as shown in the example below.

interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 redirects

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP redirects on all external interfaces as shown in the example below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1
RP/0/0/CPU0:R3(config-if)#no ipv4 redirects'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17980r288633_chk'
  tag severity: 'medium'
  tag gid: 'V-216748'
  tag rid: 'SV-216748r531087_rule'
  tag stig_id: 'CISC-RT-000190'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-17978r288634_fix'
  tag 'documentable'
  tag legacy: ['V-96703', 'SV-105841']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
