control 'SV-69211' do
  title 'CNAME records must not point to a zone with lesser security for more than six months.'
  desc "The use of CNAME records for exercises, tests, or zone-spanning aliases should be temporary (e.g., to facilitate a migration). When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias's canonical name. This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. Furthermore, in the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers and thus compounds the vulnerability."
  desc 'check', "Review the DNS server's hosted zones and respective records. Within the zone statement will be a file option that will display the name of the zone file. The record type column will display CNAME. This is usually the third or fourth field in a record depending on whether the TTL value is utilized. Without a TTL value, the CNAME type will be in the third field; otherwise, it will display as the fourth field.

Review the zone files and the DNS zone record documentation to confirm that there are no CNAME records older than 6 months.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third party Content Delivery Networks (CDN) or cloud computing platforms.  In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated (AO approval of use of a commercial cloud offering would satisfy this requirement).

If there are zone-spanning CNAME records older than 6 months and the CNAME records resolves to anything other than fully qualified domain name for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with a AO-approved and documented mission need, this is a finding."
  desc 'fix', 'Remove any zone-spanning CNAME records that have been active for more than six months.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55591r3_chk'
  tag severity: 'medium'
  tag gid: 'V-54965'
  tag rid: 'SV-69211r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000114'
  tag gtitle: 'SRG-APP-000516-DNS-000114'
  tag fix_id: 'F-59827r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
