control 'SV-228571' do
  title 'The Windows DNS name servers for a zone must be geographically dispersed.'
  desc %q(In addition to network-based separation, authoritative name servers should be dispersed geographically as well. In other words, in addition to being located on different network segments, the authoritative name servers should not all be located within the same building. One approach that some organizations follow is to locate some authoritative name servers in their own premises and others in their ISPs' data centers or in partnering organizations.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone.  If the master authoritative name server is "hidden", a secondary authoritative name server may reside in the same building as the hidden master.)
  desc 'check', 'Windows DNS Servers that are Active Directory integrated must be located where required to meet the Active Directory services. 

If all of the Windows DNS Servers are AD integrated, this check is Not Applicable.

If any or all of the Windows DNS Servers are standalone and non-AD-integrated, verify with the System Administrator their geographic location.

If any or all of the authoritative name servers are located in the same building as the master authoritative name server, and the master authoritative name server is not "hidden", this is a finding.'
  desc 'fix', 'For non-AD-integrated Windows DNS Servers, distribute secondary authoritative servers to be located in different buildings from the primary authoritative server.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-30802r505012_chk'
  tag severity: 'medium'
  tag gid: 'V-228571'
  tag rid: 'SV-228571r561297_rule'
  tag stig_id: 'WDNS-CM-000002'
  tag gtitle: 'SRG-APP-000218-DNS-000027'
  tag fix_id: 'F-30781r505013_fix'
  tag 'documentable'
  tag legacy: ['SV-73007', 'V-58577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
