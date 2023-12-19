control 'SV-205251' do
  title 'A zone file must not include resource records that resolve to a fully qualified domain name residing in another zone.'
  desc "If a name server were able to claim authority for a resource record in a domain for which it was not authoritative, this would pose a security risk. In this environment, an adversary could use illicit control of a name server to impact IP address resolution beyond the scope of that name server (i.e., by claiming authority for records outside of that server's zones). Fortunately, all but the oldest versions of BIND and most other DNS implementations do not allow for this behavior. Nevertheless, the best way to eliminate this risk is to eliminate from the zone files any records for hosts in another zone.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms.  In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated."
  desc 'check', 'Review the zone files and confirm with the DNS administrator that the hosts defined in the zone files do not resolve to hosts in another zone with its fully qualified domain name.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

If resource records are maintained that resolve to a fully qualified domain name in another zone, and the usage is not for resource records resolving to hosts that are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms with a documented and approved mission need, this is a finding.'
  desc 'fix', 'Remove any resource records in a zone file if the resource record resolves to a fully qualified domain name residing in another zone.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5518r392666_chk'
  tag severity: 'medium'
  tag gid: 'V-205251'
  tag rid: 'SV-205251r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000113'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5518r392667_fix'
  tag 'documentable'
  tag legacy: ['SV-69209', 'V-54963']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
