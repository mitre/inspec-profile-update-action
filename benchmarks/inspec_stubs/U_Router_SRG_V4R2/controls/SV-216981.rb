control 'SV-216981' do
  title 'The PE router must be configured to ignore or block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and therefore must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'Review the router configuration to determine if it will block all packets with IP options.

If the router is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the router to drop all packets with IP options.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-18211r382649_chk'
  tag severity: 'medium'
  tag gid: 'V-216981'
  tag rid: 'SV-216981r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000016'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-18209r382650_fix'
  tag 'documentable'
  tag legacy: ['V-78317', 'SV-93023']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
