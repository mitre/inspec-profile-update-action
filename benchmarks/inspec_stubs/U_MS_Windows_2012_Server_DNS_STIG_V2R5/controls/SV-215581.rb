control 'SV-215581' do
  title 'All authoritative name servers for a zone must be located on different network segments.'
  desc 'Most enterprises have an authoritative primary server and a host of authoritative secondary name servers. It is essential that these authoritative name servers for an enterprise be located on different network segments. This dispersion ensures the availability of an authoritative name server not only in situations in which a particular router or switch fails but also during events involving an attack on an entire network segment.

A network administrator may choose to use a "hidden" master authoritative server and only have secondary servers visible on the network. A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. If the master authoritative name server is "hidden", a secondary authoritative name server may reside on the same network as the hidden master.'
  desc 'check', 'Windows DNS Servers that are Active Directory-integrated must be located where required to meet the Active Directory services.

If all of the Windows DNS Servers are AD-integrated, this check is not applicable.

If any or all of the Windows DNS Servers are stand-alone and non-AD-integrated, verify with the System Administrator their geographic dispersal.

If all of the authoritative name servers are located on the same network segment, and the master authoritative name server is not "hidden", this is a finding.'
  desc 'fix', 'For non-AD-integrated Windows DNS Servers, distribute secondary authoritative servers on separate network segments from the primary authoritative server.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16775r314218_chk'
  tag severity: 'medium'
  tag gid: 'V-215581'
  tag rid: 'SV-215581r561297_rule'
  tag stig_id: 'WDNS-CM-000012'
  tag gtitle: 'SRG-APP-000516-DNS-000087'
  tag fix_id: 'F-16773r314219_fix'
  tag 'documentable'
  tag legacy: ['SV-73025', 'V-58595']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
