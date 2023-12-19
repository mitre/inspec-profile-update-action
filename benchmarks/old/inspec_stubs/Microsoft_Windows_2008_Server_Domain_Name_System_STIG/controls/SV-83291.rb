control 'SV-83291' do
  title 'The Windows 2008 DNS Servers zone files must not include CNAME records pointing to a zone with lesser security for more than six months.'
  desc "The use of CNAME records for exercises, tests, or zone-spanning aliases should be temporary (e.g., to facilitate a migration). When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias's canonical name. This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. Furthermore, in the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers and thus compounds the vulnerability."
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Review the RRs to confirm that there are no CNAME records older than 6 months.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated (AO approval of use of a commercial cloud offering would satisfy this requirement). Additional exceptions are CNAME records in a multi-domain Active Directory environment pointing to hosts in other internal domains in the same multi-domain environment.

If there are zone-spanning CNAME records older than 6 months and the CNAME records resolve to anything other than fully qualified domain names for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with an AO-approved and documented mission need, this is a finding.'
  desc 'fix', 'Remove any zone-spanning CNAME records that have been active for more than six months, which are not supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms.

In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated (AO approval of use of a commercial cloud offering would satisfy this requirement).'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59493r2_chk'
  tag severity: 'medium'
  tag gid: 'V-58621'
  tag rid: 'SV-83291r1_rule'
  tag stig_id: 'WDNS-CM-000025'
  tag gtitle: 'SRG-APP-000516-DNS-000114'
  tag fix_id: 'F-64005r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
