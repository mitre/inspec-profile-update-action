control 'SV-219058' do
  title 'All authoritative name servers for a zone must be geographically disbursed.'
  desc %q(In addition to network-based dispersion, authoritative name servers should be dispersed geographically as well. In other words, in addition to being located on different network segments, the authoritative name servers should not all be located within the same building. One approach that some organizations follow is to locate some authoritative name servers in their own premises and others in their ISPs' data centers or in partnering organizations.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. If the master authoritative name server is "hidden", a secondary authoritative name server may reside in the same building as the hidden master.)
  desc 'check', 'Review the NS records for each zone hosted and confirm that each authoritative name server is located at a different physical location than the remaining name servers.

Infoblox supports designation as a "stealth" name server, which will not have a NS record.

If all name servers, for which NS records are listed, are not physically at different locations, this is a finding.'
  desc 'fix', 'Configure the authoritative name servers to be geographically disbursed.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-20869r295944_chk'
  tag severity: 'medium'
  tag gid: 'V-219058'
  tag rid: 'SV-219058r612370_rule'
  tag stig_id: 'IDNS-7X-000260'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-20868r295945_fix'
  tag 'documentable'
  tag legacy: ['V-68543', 'SV-83033']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
