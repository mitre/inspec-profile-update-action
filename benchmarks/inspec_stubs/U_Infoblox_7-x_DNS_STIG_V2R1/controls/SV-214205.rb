control 'SV-214205' do
  title 'All authoritative name servers for a zone must be located on different network segments.'
  desc 'Most enterprises have an authoritative primary server and a host of authoritative secondary name servers. It is essential that these authoritative name servers for an enterprise be located on different network segments. This dispersion ensures the availability of an authoritative name server not only in situations in which a particular router or switch fails but also during events involving an attack on an entire network segment.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. If the master authoritative name server is "hidden", a secondary authoritative name server may reside on the same network as the hidden master.'
  desc 'check', 'Review the DNS configuration to determine all of the NS records for each zone. Based upon the NS records for each zone, determine location of each of the name servers.
Verify all authoritative name servers are located on different network segments.

If all authoritative name servers are not located on different network segments, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Zones.

Review zone settings by selecting each zone and reviewing the "Name Servers" tab to ensure all name servers are located on different network segments.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15420r295878_chk'
  tag severity: 'medium'
  tag gid: 'V-214205'
  tag rid: 'SV-214205r612370_rule'
  tag stig_id: 'IDNS-7X-000750'
  tag gtitle: 'SRG-APP-000516-DNS-000087'
  tag fix_id: 'F-15418r295879_fix'
  tag 'documentable'
  tag legacy: ['SV-83095', 'V-68605']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
