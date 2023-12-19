control 'SV-216563' do
  title 'The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled. The following command should not be found in the router configuration:

ip gratuitous-arps

Note: With Cisco IOS, Gratuitous ARP is enabled and disabled globally.

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP as shown in the example below:

R5(config)#no ip gratuitous-arps'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17798r287073_chk'
  tag severity: 'medium'
  tag gid: 'V-216563'
  tag rid: 'SV-216563r531085_rule'
  tag stig_id: 'CISC-RT-000150'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-17794r287074_fix'
  tag 'documentable'
  tag legacy: ['SV-105665', 'V-96527']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
