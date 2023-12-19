control 'SV-83221' do
  title 'The Windows 2008 DNS Server must be configured to only allow zone information that reflects the environment for which it is authoritative, to include IP ranges and IP versions.'
  desc 'DNS zone data for which a Windows 2008 DNS server is authoritative should represent the network for which it is responsible. If a Windows 2008 DNS server hosts zone records for other networks or environments, there is the possibility for the records to become invalid or stale or be redundant/conflicting with a DNS server truly authoritative for the other network environment.'
  desc 'check', 'Consult with the System Administrator to determine the IP ranges for the environment.

Log on to the DNS server using the Domain Admin or Enterprise Admin account.

If not automatically started, initialize the “Server Manager” window by clicking its icon from the bottom left corner of the screen.

Once the “Server Manager” window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the “SERVERS” section, right-click the DNS server.

From the context menu that appears, click DNS Manager.

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand Forward Lookup Zones.

From the expanded list, click to select and then right-click the zone name.

Review the zone information and compare to the IP ranges for the environment.

If any zone information is for a different IP range or domain, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

If not automatically started, initialize the “Server Manager” window by clicking its icon from the bottom left corner of the screen.

Once the “Server Manager” window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the “SERVERS” section, right-click the DNS server.

From the context menu that appears, click DNS Manager.

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand Forward Lookup Zones.

Remove any zone information which is not part of the environment.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59581r3_chk'
  tag severity: 'medium'
  tag gid: 'V-58707'
  tag rid: 'SV-83221r1_rule'
  tag stig_id: 'WDNS-SI-000001'
  tag gtitle: 'SRG-APP-000251-DNS-000037'
  tag fix_id: 'F-64091r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
