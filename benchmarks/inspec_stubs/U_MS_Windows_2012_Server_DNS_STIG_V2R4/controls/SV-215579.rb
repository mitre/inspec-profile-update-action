control 'SV-215579' do
  title 'NSEC3 must be used for all internal DNS zones.'
  desc 'NSEC records list the resource record types for the name, as well as the name of the next resource record. With this information it is revealed that the resource record type for the name queried, or the resource record name requested, does not exist. NSEC uses the actual resource record names, whereas NSEC3 uses a one-way hash of the name. In this way, walking zone data from one record to the next is prevented, at the expense of some CPU cycles both on the authoritative server as well as the resolver. To prevent giving access to an entire zone file, NSEC3 should be configured and in order to use NSEC3, RSA/SHA-1 should be used as the algorithm, as some resolvers that understand RSA/SHA-1 might not understand NSEC3. Using RSA/SHA-256 is a safe alternative.'
  desc 'check', "Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Open an elevated Windows PowerShell prompt on a DNS server using the Domain Admin or Enterprise Admin account.

Type the following command: 

PS C:\\> Get-DnsServerResourceRecord -ZoneName example.com <enter>

Where example.com is replaced with the zone hosted on the DNS Server.

All of the zone's resource records will be returned, among which should be the NSEC3 RRs, as depicted below.

If NSEC3 RRs are not returned for the zone, this is a finding.

2vf77rkf63hrgismnuvnb8... NSEC3      0                    01:00:00        [RsaSha1][False][50][F2738D980008F73C]
7ceje475rse25gppr3vphs... NSEC3      0                    01:00:00        [RsaSha1][False][50][F2738D980008F73C]"
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

If not automatically started, initialize the Server Manager window by clicking its icon from the bottom left corner of the screen.

Once the Server Manager window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the SERVERS section, right-click the DNS server.

From the context menu that appears, click DNS Manager.

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Right-click the zone, select DNSSEC, Sign the Zone.

Re-sign the zone, using an NSEC3 algorithm (RSA/SHA-1 (NSEC3), RSA/SHA-256, RSA/SHA-512).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16773r572200_chk'
  tag severity: 'medium'
  tag gid: 'V-215579'
  tag rid: 'SV-215579r561297_rule'
  tag stig_id: 'WDNS-CM-000009'
  tag gtitle: 'SRG-APP-000516-DNS-000084'
  tag fix_id: 'F-16771r572201_fix'
  tag 'documentable'
  tag legacy: ['SV-73021', 'V-58591']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
