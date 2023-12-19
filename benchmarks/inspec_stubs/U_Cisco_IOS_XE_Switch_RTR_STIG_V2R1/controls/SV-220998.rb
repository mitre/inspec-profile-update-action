control 'SV-220998' do
  title 'The Cisco switch must be configured to have Gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled. The following command should not be found in the switch configuration:

ip gratuitous-arps

Note: With Cisco IOS, Gratuitous ARP is enabled and disabled globally.

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP as shown in the example below:

SW1(config)#no ip gratuitous-arps'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22713r408788_chk'
  tag severity: 'medium'
  tag gid: 'V-220998'
  tag rid: 'SV-220998r622190_rule'
  tag stig_id: 'CISC-RT-000150'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-22702r408789_fix'
  tag 'documentable'
  tag legacy: ['SV-110817', 'V-101713']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
