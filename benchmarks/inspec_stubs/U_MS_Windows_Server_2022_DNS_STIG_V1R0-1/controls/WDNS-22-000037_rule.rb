control 'WDNS-22-000037_rule' do
  title 'The Windows DNS primary server must only send zone transfers to a specific list of secondary name servers.'
  desc 'Primary name servers also make outbound connection to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to be made only to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in a denial of service to legitimate users.

Active Directory (AD)-integrated DNS servers replicate zone information via AD replication. Non-AD-integrated DNS servers replicate zone information via zone transfers.'
  desc 'check', %q(If the DNS server hosts only AD-integrated zones and there are no non-AD-integrated DNS servers acting as secondary DNS servers for the zones, this check is not applicable.

For a non-AD-integrated DNS server:

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand "Forward Lookup Zones".

From the expanded list, click to select and then right-click the zone name.

From the displayed context menu, click the "Properties" option.

On the opened zone's properties box, go to the "Zone Transfers" tab.

On the displayed interface, determine if the "Allow zone transfers" check box is selected.

If the "Allow zone transfers" check box is not selected, this is not a finding.

If the "Allow zone transfers" check box is selected, determine if either the "Only to servers listed on the Name Servers tab" radio button is selected or the "Only to the following servers" radio button is selected.

If the "To any server" radio button is selected, this is a finding.)
  desc 'fix', %q(Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

From the displayed context menu, click the "Properties" option.

On the opened zone's properties box, go to the "Zone Transfers" tab.

On the displayed interface, select the "Allow zone transfers" check box.

Select the "Only to servers listed on the Name Servers tab" radio button OR select the "Only to the following servers" radio button.

Click "Apply".

Click "OK".)
  impact 0.5
  tag check_id: 'C-WDNS-22-000037_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000037'
  tag rid: 'WDNS-22-000037_rule'
  tag stig_id: 'WDNS-22-000037'
  tag gtitle: 'SRG-APP-000001-DNS-000001'
  tag fix_id: 'F-WDNS-22-000037_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
