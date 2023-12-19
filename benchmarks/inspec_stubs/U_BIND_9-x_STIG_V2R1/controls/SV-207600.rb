control 'SV-207600' do
  title 'On the BIND 9.x server CNAME records must not point to a zone with lesser security for more than six months.'
  desc "The use of CNAME records for exercises, tests, or zone-spanning aliases should be temporary (e.g., to facilitate a migration). When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias's canonical name. This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. Furthermore, in the case of an authoritative name server, this information is promulgated throughout the enterprise to caching servers and thus compounds the vulnerability."
  desc 'check', 'Verify that the zone files used by the BIND 9.x server do not contain resource records for a domain in which the server is not authoritative.

Inspect the "named.conf" file for the following:

zone example.com {
file "db.example.com.signed";
};

Inspect each zone file for "CNAME" records and verify with the DNS administrator that these records are less than 6 months old.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

If there are CNAME records that point to third-party Content Delivery Networks (CDNs) or cloud computing platforms without an AO-approved and documented mission need, this is a finding.

If a CNAME record is more than six months old, excluding the above, this is a finding.'
  desc 'fix', 'In the case of third-party CDNs or cloud offerings, document the mission need with the AO.

Edit the zone file.

Remove CNAME records that are older than six months that do not meet the CDN or cloud offering criteria.

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7855r283854_chk'
  tag severity: 'low'
  tag gid: 'V-207600'
  tag rid: 'SV-207600r612253_rule'
  tag stig_id: 'BIND-9X-001701'
  tag gtitle: 'SRG-APP-000516-DNS-000114'
  tag fix_id: 'F-7855r283855_fix'
  tag 'documentable'
  tag legacy: ['SV-87141', 'V-72517']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
