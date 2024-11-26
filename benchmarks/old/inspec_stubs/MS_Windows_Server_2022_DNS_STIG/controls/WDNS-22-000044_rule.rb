control 'WDNS-22-000044_rule' do
  title 'The salt value for zones signed using NSEC3 resource records (RRs) must be changed every time the zone is completely re-signed.'
  desc 'NSEC records list the resource record types for the name, as well as the name of the next resource record. With this information it is revealed that the resource record type for the name queried, or the resource record name requested, does not exist.

NSEC uses the actual resource record names, whereas NSEC3 uses a one-way hash of the name. In this way, walking zone data from one record to the next is prevented, at the expense of some CPU cycles on the authoritative server and the resolver. To prevent giving access to an entire zone file, NSEC3 should be configured. To use NSEC3, RSA/SHA-1 should be used as the algorithm, as some resolvers that understand RSA/SHA-1 might not understand NSEC3. Using RSA/SHA-256 is a safe alternative.'
  desc 'check', %q(Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

In Windows 2022, the NSEC3 salt values are automatically changed when the zone is re-signed.

To validate:
Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS Server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone. 

Review the zone's RRs in the right windowpane.

Determine the RRSIG NSEC3PARAM's Inception (in the Data column). Compare the Inception to the RRSIG DNSKEY Inception. The date and time should be the same.

If the NSEC3PARAM's Inception date and time is different than the DNSKEY Inception date and time, this is a finding.)
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand "Forward Lookup Zones".

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.

Revalidate the NSEC3PARAM Inception date and time against the DNSKEY date and time.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000044_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000044'
  tag rid: 'WDNS-22-000044_rule'
  tag stig_id: 'WDNS-22-000044'
  tag gtitle: 'SRG-APP-000516-DNS-000077'
  tag fix_id: 'F-WDNS-22-000044_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
