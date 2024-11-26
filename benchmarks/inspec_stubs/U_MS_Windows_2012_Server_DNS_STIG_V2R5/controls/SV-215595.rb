control 'SV-215595' do
  title 'Non-routable IPv6 link-local scope addresses must not be configured in any zone.'
  desc 'IPv6 link-local scope addresses are not globally routable and must not be configured in any DNS zone.  Similar to RFC1918 addresses, if a link-local scope address is inserted into a zone provided to clients, most routers will not forward this traffic beyond the local subnet.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Expand the Forward Lookup Zones folder.

Expand each zone folder and examine the host record entries. The third column titled “Data” will display the IP.

Verify this column does not contain any IP addresses that begin with the prefixes "FE8", "FE9", "FEA", or "FEB".

If any non-routable IPv6 link-local scope addresses are in any zone, this is a finding.'
  desc 'fix', 'The SA should remove any link-local addresses and replace with appropriate Site-Local or Global scope addresses.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16789r572398_chk'
  tag severity: 'medium'
  tag gid: 'V-215595'
  tag rid: 'SV-215595r744231_rule'
  tag stig_id: 'WDNS-CM-000026'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-16787r314261_fix'
  tag 'documentable'
  tag legacy: ['SV-73053', 'V-58623']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
