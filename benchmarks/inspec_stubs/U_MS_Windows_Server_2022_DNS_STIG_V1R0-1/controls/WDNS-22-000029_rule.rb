control 'WDNS-22-000029_rule' do
  title 'The Windows 2022 DNS Servers zone files must not include resource records that resolve to a fully qualified domain name residing in another zone.'
  desc "If a name server could claim authority for a resource record in a domain for which it was not authoritative, this would pose a security risk. In this environment, an adversary could use illicit control of a name server to impact IP address resolution beyond the scope of that name server (i.e., by claiming authority for records outside of that server's zones). Fortunately, all but the oldest versions of BIND and most other DNS implementations do not allow for this behavior. The best way to eliminate this risk is to eliminate from the zone files any records for hosts in another zone.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party content delivery networks (CDNs) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated."
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.
 
Confirm with the DNS administrator that the hosts defined in the zone files do not resolve to hosts in another zone with its fully qualified domain name.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party CDNs or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated. Additional exceptions are CNAME records in a multidomain Active Directory environment pointing to hosts in other internal domains in the same multidomain environment.

If resource records are maintained that resolve to a fully qualified domain name in another zone, and the usage is not for resource records resolving to hosts that are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party CDNs or cloud computing platforms with a documented and approved mission need, this is a finding.'
  desc 'fix', 'Remove any resource records in a zone file if the resource record resolves to a fully qualified domain name residing in another zone.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000029_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000029'
  tag rid: 'WDNS-22-000029_rule'
  tag stig_id: 'WDNS-22-000029'
  tag gtitle: 'SRG-APP-000516-DNS-000113'
  tag fix_id: 'F-WDNS-22-000029_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
