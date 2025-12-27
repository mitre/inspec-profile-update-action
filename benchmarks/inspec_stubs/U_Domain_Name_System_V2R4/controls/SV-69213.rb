control 'SV-69213' do
  title 'All authoritative name servers for a zone must be geographically disbursed.'
  desc %q(In addition to network-based dispersion, authoritative name servers should be dispersed geographically as well. In other words, in addition to being located on different network segments, the authoritative name servers should not all be located within the same building. One approach that some organizations follow is to locate some authoritative name servers in their own premises and others in their ISPs' data centers or in partnering organizations.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone.  If the master authoritative name server is "hidden", a secondary authoritative name server may reside in the same building as the hidden master.)
  desc 'check', 'Review the NS records for each zone hosted and confirm that each authoritative name server is located at a different physical location than the remaining name servers.

If the master, or primary, authoritative name server is configured to be "hidden", it will not have an NS record. One other name server may be at the same physical location as the hidden name server.

If all name servers, for which NS records are listed, are not physically at different locations, this is a finding.'
  desc 'fix', 'Physically move name servers so that they are geographically at different locations. If moving a name server is not feasible, one of the co-located name servers could be reconfigured to be hidden.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54967'
  tag rid: 'SV-69213r1_rule'
  tag stig_id: 'SRG-APP-000218-DNS-000027'
  tag gtitle: 'SRG-APP-000218-DNS-000027'
  tag fix_id: 'F-59829r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
