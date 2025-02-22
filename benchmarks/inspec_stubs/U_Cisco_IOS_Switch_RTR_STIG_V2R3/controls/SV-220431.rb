control 'SV-220431' do
  title 'The Cisco switch must be configured to have gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled. The following command should not be found in the switch configuration: 

ip gratuitous-arps 

Note: With Cisco IOS, gratuitous ARP is enabled and disabled globally. 

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP as shown in the example below: 

SW1(config)#no ip gratuitous-arps'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22146r508378_chk'
  tag severity: 'medium'
  tag gid: 'V-220431'
  tag rid: 'SV-220431r856233_rule'
  tag stig_id: 'CISC-RT-000150'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-22135r508379_fix'
  tag 'documentable'
  tag legacy: ['SV-110709', 'V-101605']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
