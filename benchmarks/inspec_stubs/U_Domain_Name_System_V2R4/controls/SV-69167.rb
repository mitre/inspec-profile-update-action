control 'SV-69167' do
  title 'NSEC3 must be used for all internal DNS zones.'
  desc %q(To ensure that RRs associated with a query are really missing in a zone file and have not been removed in transit, the DNSSEC mechanism provides a means for authenticating the nonexistence of an RR. It generates a special RR called an NSEC (or NSEC3) RR that lists the RRTypes associated with an owner name as well as the next name in the zone file. It sends this special RR, along with its signatures, to the resolving name server. By verifying the signature, a DNSSEC-aware resolving name server can determine which authoritative owner name exists in a zone and which authoritative RRTypes exist at those owner names.

IETF's design criteria consider DNS data to be public. Confidentiality is not one of the security goals of DNSSEC. DNSSEC is not designed to directly protect against denial-of-service threats but does so indirectly by providing message integrity and source authentication. An artifact of how DNSSEC performs negative responses allows a client to map all the names in a zone (zone walking). 

A zone which contains zone data that the administrator does not want to be made public should use the NSEC3 RR option for providing authenticated denial of existence.



If DNSSEC is enabled for a server, the ability to verify a particular server which may attempt to update the DNS server actually exists. This is done through the use of NSEC3 records to provide an "authenticated denial of existence" for specific systems whose addresses indicate that they lie within a particular zone.)
  desc 'check', "Review the zone file's configuration for internal zones and confirm the NSEC3 RR option is used to provide authenticated denial of existence.

If the NSEC3 RR option is not used for internal zones, this is a finding."
  desc 'fix', 'Configure all internal zones to use the NSEC3 RR option for authenticated denial of existence.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55547r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54921'
  tag rid: 'SV-69167r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000084'
  tag gtitle: 'SRG-APP-000516-DNS-000084'
  tag fix_id: 'F-59783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
