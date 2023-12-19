control 'SV-214219' do
  title 'CNAME records must not point to a zone with lesser security for more than six months.'
  desc "The use of CNAME records for exercises, tests, or zone-spanning aliases should be temporary (e.g., to facilitate a migration). When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias's canonical name. This configuration also reduces the speed of client resolution because it requires a second look-up after obtaining the canonical name. Furthermore, in the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers and thus compounds the vulnerability.
The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated (AO approval of use of a commercial cloud offering would satisfy this requirement). Additional exceptions are CNAME records in a multi-domain Active Directory environment pointing to hosts in other internal domains in the same multi-domain environment."
  desc 'check', 'Infoblox DNS records the creation date of every resource record, including CNAME records in the system and the TimeStamp is attached to the CNAME object. Infoblox can also record the date when the last time this record was used or queried. CNAME records can be removed by the admin when they reach their 6 month maturity date.

Navigate to Grid Manager >> Administration >> Logs >> Audit Log >> Filter >> Object Type=CNAME Record, + Action=CREATED, + TimeStamp=Before=6months Ago

If there are zone-spanning CNAME records older than 6 months and the CNAME records resolve to anything other than fully qualified domain names for glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with an AO-approved and documented mission need, this is a finding.'
  desc 'fix', 'Navigate to Grid Manager >> Administration >> Logs >> Audit Log >> Filter >> Object Type=CNAME Record, + Action=CREATED, + TimeStamp=Before=6months Ago

Remove any zone-spanning CNAME records that have been active for more than six months.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15434r295920_chk'
  tag severity: 'medium'
  tag gid: 'V-214219'
  tag rid: 'SV-214219r612370_rule'
  tag stig_id: 'IDNS-7X-000940'
  tag gtitle: 'SRG-APP-000516-DNS-000114'
  tag fix_id: 'F-15432r295921_fix'
  tag 'documentable'
  tag legacy: ['SV-83123', 'V-68633']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
