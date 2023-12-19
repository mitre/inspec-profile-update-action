control 'SV-233864' do
  title 'All authoritative name servers for a zone must be located on different network segments.'
  desc 'Most enterprises have an authoritative primary server and a host of authoritative secondary name servers. It is essential that these authoritative name servers for an enterprise be located on different network segments. This dispersion ensures the availability of an authoritative name server not only in situations in which a particular router or switch fails but also during events involving an attack on an entire network segment.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server in which the IP address does not appear in the name server set for a zone. If the master authoritative name server is "hidden", a secondary authoritative name server may reside on the same network as the hidden master.'
  desc 'check', 'Review the DNS configuration to determine all of the name server (NS) records for each zone. Based on the NS records for each zone and network architecture, determine the location of each of the name servers. 

1. Navigate to Data Management >> DNS >> Zones. 
2. Select the zone to review. 
3. Select the "Name Servers" tab.  

If all authoritative name servers are not located on different network segments, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones. 
2. Review zone settings by selecting each zone and reviewing the "Name Servers" tab to ensure all name servers are located on different network segments.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37049r611112_chk'
  tag severity: 'medium'
  tag gid: 'V-233864'
  tag rid: 'SV-233864r621666_rule'
  tag stig_id: 'IDNS-8X-400006'
  tag gtitle: 'SRG-APP-000516-DNS-000087'
  tag fix_id: 'F-37014r611113_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
