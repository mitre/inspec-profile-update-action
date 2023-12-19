control 'WDNS-22-000016_rule' do
  title 'The Windows 2022 DNS Servers zone files must have NS records that point to active name servers authoritative for the domain specified in that record.'
  desc "Poorly constructed NS records pose a security risk because they create conditions under which an adversary might be able to provide the missing authoritative name services that are improperly specified in the zone file. The adversary could issue bogus responses to queries that clients would accept because they learned of the adversary's name server from a valid authoritative name server, one that need not be compromised for this attack to be successful. 

The list of secondary servers must remain current within 72 hours of any changes to the zone architecture that would affect the list of secondaries. If a secondary server has been retired or is not operational but remains on the list, an adversary might have a greater opportunity to impersonate that secondary without detection, rather than if the secondary was online. For example, the adversary may be able to spoof the retired secondary's IP address without an IP address conflict, which would not be likely to occur if the true secondary were active."
  desc 'check', 'Note: This check is not applicable if Windows DNS Server is only serving as a caching server and does not host any zones authoritatively.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Review the NS records for the zone.

Verify each of the name servers, represented by the NS records, is active.

At a command prompt on any system, type:

nslookup <enter>;

At the nslookup prompt, type: 

server ###.###.###.### <enter>;
(where the ###.###.###.### is replaced by the IP of each NS record) 

Enter a FQDN for a known host record in the zone.

If the NS server does not respond at all or responds with a nonauthoritative answer, this is a finding.'
  desc 'fix', 'If DNS servers are Active Directory (AD) integrated, troubleshoot and remedy the replication problem where the nonresponsive name server is not being updated.

If DNS servers are not AD integrated, log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone. 

Review the NS records for the zone.

Select the NS record for the nonresponsive name server and remove the record.'
  impact 0.7
  tag check_id: 'C-WDNS-22-000016_chk'
  tag severity: 'high'
  tag gid: 'WDNS-22-000016'
  tag rid: 'WDNS-22-000016_rule'
  tag stig_id: 'WDNS-22-000016'
  tag gtitle: 'SRG-APP-000516-DNS-000085'
  tag fix_id: 'F-WDNS-22-000016_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
