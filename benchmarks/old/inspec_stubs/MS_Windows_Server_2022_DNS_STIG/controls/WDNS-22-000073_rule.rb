control 'WDNS-22-000073_rule' do
  title 'The Windows 2022 DNS Server must be configured to only allow zone information that reflects the environment for which it is authoritative, including IP ranges and IP versions.'
  desc 'DNS zone data for which a Windows 2022 DNS Server is authoritative should represent the network for which it is responsible. If a Windows 2022 DNS Server hosts zone records for other networks or environments, the records could become invalid or stale or be redundant/conflicting with a DNS server truly authoritative for the other network environment.'
  desc 'check', 'Consult with the system administrator to determine the IP ranges for the environment.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

If not automatically started, initialize the "Server Manager" window by clicking its icon from the bottom left corner of the screen.

Once the "Server Manager" window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the context menu that appears, click "DNS Manager".

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

From the expanded list, click to select and then right-click the zone name.

Review the zone information and compare it to the IP ranges for the environment.

If any zone information is for a different IP range or domain, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

If not automatically started, initialize the "Server Manager" window by clicking its icon from the bottom left corner of the screen.

Once the "Server Manager" window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the context menu that appears, click "DNS Manager".

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

Remove any zone information that is not part of the environment.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000073_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000073'
  tag rid: 'WDNS-22-000073_rule'
  tag stig_id: 'WDNS-22-000073'
  tag gtitle: 'SRG-APP-000251-DNS-000037'
  tag fix_id: 'F-WDNS-22-000073_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
