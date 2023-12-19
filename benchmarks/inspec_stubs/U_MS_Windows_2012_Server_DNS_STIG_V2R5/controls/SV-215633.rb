control 'SV-215633' do
  title 'The Windows 2012 DNS Server must use DNS Notify to prevent denial of service through increase in workload.'
  desc 'In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time.'
  desc 'check', %q(Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

In the list of hosts, review the Name Server (NS) records. Determine if any of the hosts listed as NS records are non-AD-integrated servers.

If the DNS server only hosts AD-integrated zones and there are not any non-AD-integrated DNS servers acting as secondary DNS servers for the zones, this check is not applicable.

For a non-AD-integrated DNS server, right click on the Forward Lookup zone and select “Properties”.
On the opened zone's properties box, go to the “Zone Transfers” tab.

On the displayed interface, verify if the "Allow zone transfers" check box is selected.

If the "Allow zone transfers" check box is selected, click on the “Notify” button and verify “Automatically notify with Servers” is listed on the “Name Servers” tab is selected.

If the “Notify” button is not enabled for non-AD-integrated DNS servers, this is a finding.)
  desc 'fix', %q(Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

In the list of hosts, review the Name Server (NS) records. Determine if any of the hosts listed as NS records are non-AD-integrated servers.

If the DNS server only hosts AD-integrated zones and there are not any non-AD-integrated DNS servers acting as secondary DNS servers for the zones, this check is Not Applicable.

For a non-AD-integrated DNS server, Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand Forward Lookup Zones.

From the expanded list, click to select and then right-click the zone name.

From the displayed context menu, click the “Properties” option.

On the opened zone's properties box, go to the “Zone Transfers” tab.

On the displayed interface, verify if the "Allow zone transfers" check box is selected.

If the "Allow zone transfers" check box is selected, click on the “Notify” button and enable Notify to the non-AD-integrated DNS servers.)
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16827r572276_chk'
  tag severity: 'medium'
  tag gid: 'V-215633'
  tag rid: 'SV-215633r561297_rule'
  tag stig_id: 'WDNS-SC-000027'
  tag gtitle: 'SRG-APP-000247-DNS-000036'
  tag fix_id: 'F-16825r572277_fix'
  tag 'documentable'
  tag legacy: ['SV-73129', 'V-58699']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
