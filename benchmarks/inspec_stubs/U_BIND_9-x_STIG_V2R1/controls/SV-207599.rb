control 'SV-207599' do
  title 'On the BIND 9.x server a zone file must not include resource records that resolve to a fully qualified domain name residing in another zone.'
  desc "If a name server were able to claim authority for a resource record in a domain for which it was not authoritative, this would pose a security risk. In this environment, an adversary could use illicit control of a name server to impact IP address resolution beyond the scope of that name server (i.e., by claiming authority for records outside of that server's zones). Fortunately, all but the oldest versions of BIND and most other DNS implementations do not allow for this behavior. Nevertheless, the best way to eliminate this risk is to eliminate from the zone files any records for hosts in another zone."
  desc 'check', 'Verify that the zone files used by the BIND 9.x server do not contain resource records for a domain in which the server is not authoritative.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

Inspect the "named.conf" file to identify the zone files, for which the server is authoritative:

zone example.com {
file "db.example.com.signed";
};

Inspect each zone file for which the server is authoritative. 

If there are CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms without an AO-approved and documented mission need, this is a finding.

If a zone file contains records that resolve to another zone, excluding the above, this is a finding.'
  desc 'fix', 'In the case of third-party CDNs or cloud offerings, document the mission need with the AO.

Edit the zone file.

Remove any record that points to a different zone, with the exception of approved CDNs or cloud offerings.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7854r283851_chk'
  tag severity: 'medium'
  tag gid: 'V-207599'
  tag rid: 'SV-207599r612253_rule'
  tag stig_id: 'BIND-9X-001700'
  tag gtitle: 'SRG-APP-000516-DNS-000113'
  tag fix_id: 'F-7854r283852_fix'
  tag 'documentable'
  tag legacy: ['SV-87139', 'V-72515']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
