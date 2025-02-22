control 'WDNS-22-000001_rule' do
  title 'The Windows 2022 DNS Server must restrict incoming dynamic update requests to known clients.'
  desc "Limiting the number of concurrent sessions reduces the risk of denial of service (DoS) on any system.

A DNS server's function requires it to be able to handle multiple sessions at a time, so limiting concurrent sessions could impact availability.

Primary name servers must be configured to limit the actual hosts from which they will accept dynamic updates and zone transfer requests, and all name servers should be configured to limit the hosts from/to which they receive/send zone transfers. Restricting sessions to known hosts will mitigate the DoS vulnerability."
  desc 'check', %q(Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc". 

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Once selected, right-click the name of the zone.

From the displayed context menu, click the "Properties" option.

On the opened domain's properties box, click the "General" tab.

Verify the "Type:" is "Active Directory-Integrated".

Verify "Dynamic updates" has "Secure only" selected.

If the zone is "Active Directory-Integrated" and "Dynamic updates" are not configured for "Secure only", this is a finding.)
  desc 'fix', %q(Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Once selected, right-click the name of the zone.

From the displayed context menu, click the "Properties" option.

On the opened domain's properties box, click the "General" tab.

If the "Type:" is not "Active Directory-Integrated", configure the zone for Active Directory integration.

Select "Secure only" from the "Dynamic updates:" drop-down list.)
  impact 0.5
  tag check_id: 'C-WDNS-22-000001_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000001'
  tag rid: 'WDNS-22-000001_rule'
  tag stig_id: 'WDNS-22-000001'
  tag gtitle: 'SRG-APP-000001-DNS-000115'
  tag fix_id: 'F-WDNS-22-000001_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
