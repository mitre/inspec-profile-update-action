control 'SV-215591' do
  title 'The Windows 2012 DNS Server authoritative for local zones must only point root hints to the DNS servers that host the internal root domain.'
  desc "All caching name servers must be authoritative for the root zone because, without this starting point, they would have no knowledge of the DNS infrastructure and thus would be unable to respond to any queries. The security risk is that an adversary could change the root hints and direct the caching name server to a bogus root server. At that point, every query response from that name server is suspect, which would give the adversary substantial control over the network communication of the name servers' clients. When authoritative servers are sent queries for zones that they are not authoritative for, and they are configured as a non-caching server (as recommended), they can either be configured to return a referral to the root servers or they can be configured to refuse to answer the query. The recommendation is to configure authoritative servers to refuse to answer queries for any zones for which they are not authoritative. This is more efficient for the server and allows it to spend more of its resources doing what its intended purpose is, answering authoritatively for its zone."
  desc 'check', 'Note: If the Windows DNS server is in the classified network, this check is Not Applicable.
Log on to the authoritative DNS server using the Domain Admin or Enterprise Admin account.
Press Windows Key + R, execute dnsmgmt.msc.
Right-click the DNS server, select “Properties”.
Select the "Root Hints" tab.
Verify the "Root Hints" is either empty or only has entries for internal zones under "Name servers:". All Internet root server entries must be removed.
If "Root Hints" is not empty or entries on the "Root Hints" tab under "Name servers:" are external to the local network, this is a finding.'
  desc 'fix', 'Log on to the authoritative DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.
Right-click the DNS server, select "Properties".
Select the "Root Hints" tab.
Remove the root hints from the DNS Manager, the CACHE.DNS file and from Active Directory for name servers outside of the internal network. 
Replace the existing root hints with new root hints of internal servers. 
If the DNS server is forwarding, click to select the : "Do not use recursion for this domain" check box on the "Forwarders" tab in DNS Manager to make sure that the root hints will not be used.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16785r314248_chk'
  tag severity: 'medium'
  tag gid: 'V-215591'
  tag rid: 'SV-215591r561297_rule'
  tag stig_id: 'WDNS-CM-000022'
  tag gtitle: 'SRG-APP-000516-DNS-000102'
  tag fix_id: 'F-16783r314249_fix'
  tag 'documentable'
  tag legacy: ['SV-73045', 'V-58615']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
