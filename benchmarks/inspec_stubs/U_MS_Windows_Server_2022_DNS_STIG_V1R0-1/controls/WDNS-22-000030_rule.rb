control 'WDNS-22-000030_rule' do
  title "The Windows 2022 DNS Server's zone files must not include CNAME records pointing to a zone with lesser security for more than six months."
  desc "The use of CNAME records for exercises, tests, or zone-spanning (pointing to zones with lesser security) aliases should be temporary (e.g., to facilitate a migration) and not be in place for more than six months. 

When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias's canonical name. This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. In the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers, which compounds the vulnerability."
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Review the resource records to confirm there are no CNAME records older than six months.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDNs) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated. (Authorizing Official approval of use of a commercial cloud offering would satisfy this requirement.) Additional exceptions are CNAME records in a multidomain Active Directory environment pointing to hosts in other internal domains in the same multidomain environment.

If there are zone-spanning (i.e., zones of lesser security) CNAME records older than six months and the CNAME records resolve to anything other than fully qualified domain names for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party CDNs or cloud computing platforms with an AO-approved and documented mission need, this is a finding.'
  desc 'fix', 'Remove any zone-spanning CNAME records that have been active for more than six months, which are not supporting zone delegations, CNAME records supporting a system migration, or CNAME records pointing to third-party CDNs or cloud computing platforms.

In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated (AO approval of use of a commercial cloud offering would satisfy this requirement).'
  impact 0.5
  tag check_id: 'C-WDNS-22-000030_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000030'
  tag rid: 'WDNS-22-000030_rule'
  tag stig_id: 'WDNS-22-000030'
  tag gtitle: 'SRG-APP-000516-DNS-000114'
  tag fix_id: 'F-WDNS-22-000030_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
