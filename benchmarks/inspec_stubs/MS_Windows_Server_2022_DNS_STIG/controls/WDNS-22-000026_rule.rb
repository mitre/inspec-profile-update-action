control 'WDNS-22-000026_rule' do
  title 'The Windows 2022 DNS Server must implement internal/external role separation.'
  desc 'DNS servers with an internal role only process name/address resolution requests from within the organization (i.e., internal clients). DNS servers with an external role only process name/address resolution information requests from clients external to the organization (i.e., on the external networks, including the internet). 

The set of clients that can access an authoritative DNS server in a particular role is specified by the organization using address ranges, explicit access control lists, etc. To protect internal DNS resource information, it is important to isolate the requests to internal DNS servers. Separating internal and external roles in DNS prevents address space that is private (e.g., 10.0.0.0/24) or otherwise concealed by some form of Network Address Translation from leaking into the public DNS system.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, review each zone.

Consult with the DNS Admin to determine if any of the zones also have hostnames that need to be resolved from the external network.

If the zone is split between internal and external networks, verify separate DNS servers have been implemented for each network.

If internal and external DNS servers have not been implemented for zones that require resolution from both the internal and external networks, this is a finding.'
  desc 'fix', 'Configure separate DNS servers for each of the external and internal networks.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000026_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000026'
  tag rid: 'WDNS-22-000026_rule'
  tag stig_id: 'WDNS-22-000026'
  tag gtitle: 'SRG-APP-000516-DNS-000101'
  tag fix_id: 'F-WDNS-22-000026_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
