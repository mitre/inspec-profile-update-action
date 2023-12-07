control 'WDNS-22-000018_rule' do
  title 'All authoritative name servers for a zone must have the same version of zone information.'
  desc 'The only protection approach for content control of a DNS zone file is the use of a zone file integrity checker. The effectiveness of integrity checking using a zone file integrity checker depends on the database of constraints built into the checker. The deployment process consists of developing these constraints with the right logic, and the only determinant of the truth value of these logical predicates is the parameter values for certain key fields in the format of various RRTypes.

The serial number in the SOA RDATA is used to indicate to secondary name servers that a change to the zone has occurred and a zone transfer should be performed. It should always be increased whenever a change is made to the zone data. DNS NOTIFY must be enabled on the primary authoritative name server.'
  desc 'check', 'Note: Due to the manner in which Active Directory replication increments SOA records for zones when transferring zone information via Active Directory (AD) replication, this check is not applicable for AD-integrated zones.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Review the SOA information for the zone and obtain the Serial Number.

Access each secondary name server for the same zone and review the SOA information.

Verify the Serial Number is the same on all authoritative name servers.

If the Serial Number is not the same on one or more authoritative name servers, this is a finding.'
  desc 'fix', 'If all DNS servers are AD integrated, determine why the replication is not taking place to the out-of-sync secondary name servers and mitigate the issue.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Initiate a zone transfer to all secondary name servers for the zone.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000018_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000018'
  tag rid: 'WDNS-22-000018_rule'
  tag stig_id: 'WDNS-22-000018'
  tag gtitle: 'SRG-APP-000516-DNS-000088'
  tag fix_id: 'F-WDNS-22-000018_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
