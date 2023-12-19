control 'SV-221128' do
  title 'The Cisco PE switch must be configured to ignore or drop all packets with any IP options.'
  desc 'Packets with IP options are not fast-switched and therefore must be punted to the switch processor. Hackers who initiate denial-of-service (DoS) attacks on switches commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the switch. The end result is a reduction in the effects of the DoS attack on the switch and on downstream switches.'
  desc 'check', 'In Cisco NX-OS, all packets with any header option other than the “source-route” header option are dropped. By default, ipv4 source routing is enabled. Verify that source routing is disabled via the following command: 

no ip source-route

If the switch is not configured to drop all packets with IP option source routing, this is a finding.'
  desc 'fix', 'Configure the switch to drop all packets with IP option source routing.

SW1(config)# no ip source-route 
SW1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22843r409873_chk'
  tag severity: 'medium'
  tag gid: 'V-221128'
  tag rid: 'SV-221128r856657_rule'
  tag stig_id: 'CISC-RT-000750'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-22832r409874_fix'
  tag 'documentable'
  tag legacy: ['SV-111075', 'V-101971']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
