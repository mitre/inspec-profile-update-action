control 'SV-205232' do
  title 'All authoritative name servers for a zone must be located on different network segments.'
  desc 'Most enterprises have an authoritative primary server and a host of authoritative secondary name servers. It is essential that these authoritative name servers for an enterprise be located on different network segments. This dispersion ensures the availability of an authoritative name server not only in situations in which a particular router or switch fails but also during events involving an attack on an entire network segment.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. If the master authoritative name server is "hidden", a secondary authoritative name server may reside on the same network as the hidden master.'
  desc 'check', 'Review the DNS configuration files to determine all of the NS records for each zone. Based upon the NS records for each zone, determine location of each of the name servers. Verify all authoritative name servers are located on different network segments.

If two authoritative name servers are found on the same network segment, and one of those two is hidden, this is not a finding.

If any authoritative name servers are located on the same network segment as another authoritative name server, this is a finding.'
  desc 'fix', 'Locate all visible (non-hidden) name servers to be on different network segments.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5499r392609_chk'
  tag severity: 'medium'
  tag gid: 'V-205232'
  tag rid: 'SV-205232r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000087'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5499r392610_fix'
  tag 'documentable'
  tag legacy: ['SV-69173', 'V-54927']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
