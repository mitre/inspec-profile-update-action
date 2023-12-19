control 'WDNS-22-000017_rule' do
  title 'All authoritative name servers for a zone must be located on different network segments.'
  desc 'Most enterprises have an authoritative primary server and a host of authoritative secondary name servers. It is essential that these authoritative name servers for an enterprise be located on different network segments. This dispersion ensures the availability of an authoritative name server not only in situations in which a particular router or switch fails but also during events involving an attack on an entire network segment.

A network administrator may choose to use a "hidden" primary authoritative server and have only secondary servers visible on the network. A hidden primary authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. If the primary authoritative name server is hidden, a secondary authoritative name server may reside on the same network as the hidden primary.'
  desc 'check', 'Windows DNS Servers that are Active Directory (AD) integrated must be located where required to meet the Active Directory services.

If all of the Windows DNS Servers are AD integrated, this check is not applicable.

If any or all the Windows DNS Servers are standalone and non-AD integrated, verify their geographic location with the system administrator.

If all of the authoritative name servers are located on the same network segment and the primary authoritative name server is not "hidden", this is a finding.'
  desc 'fix', 'For non-AD-integrated Windows DNS Servers, distribute secondary authoritative servers on separate network segments from the primary authoritative server.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000017_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000017'
  tag rid: 'WDNS-22-000017_rule'
  tag stig_id: 'WDNS-22-000017'
  tag gtitle: 'SRG-APP-000516-DNS-000087'
  tag fix_id: 'F-WDNS-22-000017_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
