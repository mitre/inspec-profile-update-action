control 'SV-215588' do
  title 'Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.'
  desc 'Authoritative name servers (especially primary name servers) should be configured with an allow-transfer access control sub statement designating the list of hosts from which zone transfer requests can be accepted. These restrictions address the denial-of-service threat and potential exploits from unrestricted dissemination of information about internal resources. Based on the need-to-know, the only name servers that need to refresh their zone files periodically are the secondary name servers. Zone transfer from primary name servers should be restricted to secondary name servers. The zone transfer should be completely disabled in the secondary name servers. The address match list argument for the allow-transfer sub statement should consist of IP addresses of secondary name servers and stealth secondary name servers.'
  desc 'check', 'Verify whether the authoritative primary name server is AD-integrated.

Verify whether all secondary name servers for every zone for which the primary name server is authoritative are all AD-integrated in the same Active Directory.

If the authoritative primary name server is AD-integrated and all secondary name servers also part of the same AD, this check is not a finding since AD handles the replication of DNS data.

If one or more of the secondary name servers are non-AD integrated, verify the primary name server is configured to only send zone transfers to a specific list of secondary name servers.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Right-click the zone and select “Properties”.

Select the “Zone Transfers” tab.

If the "Allow zone transfers:" check box is not selected, this is not a finding.

If the "Allow zone transfers:" check box is selected, verify either "Only to servers listed on the Name Server tab" or "Only to the following servers" is selected.

If the "To any server" option is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Right-click the zone and select “Properties”.

Select the "Zone Transfers" tab.

Select the "Only to servers listed on the Name Server tab" or "Only to the following servers" check box or deselect the "Allow zone transfers" check box.

Click “OK”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16782r572218_chk'
  tag severity: 'medium'
  tag gid: 'V-215588'
  tag rid: 'SV-215588r561297_rule'
  tag stig_id: 'WDNS-CM-000019'
  tag gtitle: 'SRG-APP-000516-DNS-000095'
  tag fix_id: 'F-16780r572219_fix'
  tag 'documentable'
  tag legacy: ['SV-73039', 'V-58609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
