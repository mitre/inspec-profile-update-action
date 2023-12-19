control 'SV-217001' do
  title 'The Cisco PE router must be configured to ignore or drop all packets with any IP options.'
  desc 'Packets with IP options are not fast-switched and therefore must be punted to the router processor. Hackers who initiate denial of service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'Review the router configuration to determine if it will ignore or drop all packets with IP options as shown in the examples below:

ip options drop
or
ip options ignore

If the router is not configured to drop or block all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the router to ignore or drop all packets with IP options as shown in the examples below:

R4(config)#ip options ignore 

or

R4(config)#ip options drop'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-18231r288165_chk'
  tag severity: 'medium'
  tag gid: 'V-217001'
  tag rid: 'SV-217001r531086_rule'
  tag stig_id: 'CISC-RT-000750'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-18229r288166_fix'
  tag 'documentable'
  tag legacy: ['SV-106137', 'V-96999']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
