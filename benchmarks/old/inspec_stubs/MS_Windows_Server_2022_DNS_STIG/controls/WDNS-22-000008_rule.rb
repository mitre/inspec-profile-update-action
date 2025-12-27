control 'WDNS-22-000008_rule' do
  title 'The Windows DNS name servers for a zone must be geographically dispersed.'
  desc %q(In addition to network-based separation, authoritative name servers should be dispersed geographically. In other words, in addition to being located on different network segments, the authoritative name servers should not all be located in the same building. One approach is to locate some authoritative name servers in their own premises and others in their internet service provider's data centers or in partnering organizations.

A network administrator may choose to use a "hidden" primary authoritative server and have only secondary servers visible on the network. A hidden primary authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. If the primary authoritative name server is hidden, a secondary authoritative name server may reside in the same building as the hidden primary.)
  desc 'check', 'Windows DNS Servers that are Active Directory (AD) integrated must be located where required to meet the AD services. 

If all the Windows DNS Servers are AD integrated, this check is not applicable.

If any or all the Windows DNS Servers are standalone and non-AD integrated, verify their geographic location with the system administrator.

If any or all of the authoritative name servers are located in the same building as the primary authoritative name server and the primary authoritative name server is not "hidden", this is a finding.'
  desc 'fix', 'For non-AD integrated Windows DNS Servers, distribute secondary authoritative servers to be in different buildings from the primary authoritative server.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000008_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000008'
  tag rid: 'WDNS-22-000008_rule'
  tag stig_id: 'WDNS-22-000008'
  tag gtitle: 'SRG-APP-000218-DNS-000027'
  tag fix_id: 'F-WDNS-22-000008_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
