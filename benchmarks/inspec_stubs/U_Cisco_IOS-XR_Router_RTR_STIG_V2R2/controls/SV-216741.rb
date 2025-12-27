control 'SV-216741' do
  title 'The Cisco router must be configured to have all non-essential capabilities disabled.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the router configuration to verify that the router does not have any unnecessary or non-secure services enabled. For example, the following commands should not be in the configuration:

service ipv4 tcp-small-servers max-servers 10
service ipv4 udp-small-servers max-servers 10
http client vrf xxxxx
telnet vrf default ipv4 server max-servers 1

If any unnecessary services are enabled, this is a finding.'
  desc 'fix', 'Disable the following services if enabled as shown in the example below.

RP/0/0/CPU0:R3(config)#no service ipv4 tcp-small-servers
RP/0/0/CPU0:R3(config)#no service ipv4 udp-small-servers
RP/0/0/CPU0:R3(config)#no http client vrf xxxxx
RP/0/0/CPU0:R3(config)#no telnet ipv4 server'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17973r288615_chk'
  tag severity: 'low'
  tag gid: 'V-216741'
  tag rid: 'SV-216741r531087_rule'
  tag stig_id: 'CISC-RT-000070'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-17971r288616_fix'
  tag 'documentable'
  tag legacy: ['SV-105827', 'V-96689']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
