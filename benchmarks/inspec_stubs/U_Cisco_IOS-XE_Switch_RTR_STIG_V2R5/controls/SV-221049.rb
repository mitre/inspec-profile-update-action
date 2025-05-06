control 'SV-221049' do
  title 'The Cisco PE switch must be configured to ignore or drop all packets with any IP options.'
  desc 'Packets with IP options are not fast-switched and therefore must be punted to the switch processor. Hackers who initiate denial-of-service (DoS) attacks on switches commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the switch. The end result is a reduction in the effects of the DoS attack on the switch and on downstream switches.'
  desc 'check', 'Review the switch configuration to determine if it will ignore or drop all packets with IP options as shown in the examples below:

ip options drop
or
ip options ignore

If the switch is not configured to drop or block all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the switch to ignore or drop all packets with IP options as shown in the examples below:

SW1(config)#ip options ignore 

or

SW1(config)#ip options drop'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22764r408941_chk'
  tag severity: 'medium'
  tag gid: 'V-221049'
  tag rid: 'SV-221049r856420_rule'
  tag stig_id: 'CISC-RT-000750'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-22753r408942_fix'
  tag 'documentable'
  tag legacy: ['SV-110919', 'V-101815']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
