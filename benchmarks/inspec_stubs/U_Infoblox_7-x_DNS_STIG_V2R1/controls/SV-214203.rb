control 'SV-214203' do
  title 'NSEC3 must be used for all internal DNS zones.'
  desc %q(To ensure that RRs associated with a query are really missing in a zone file and have not been removed in transit, the DNSSEC mechanism provides a means for authenticating the nonexistence of an RR. It generates a special RR called an NSEC (or NSEC3) RR that lists the RRTypes associated with an owner name as well as the next name in the zone file. It sends this special RR, along with its signatures, to the resolving name server. By verifying the signature, a DNSSEC-aware resolving name server can determine which authoritative owner name exists in a zone and which authoritative RRTypes exist at those owner names.

IETF's design criteria consider DNS data to be public. Confidentiality is not one of the security goals of DNSSEC. DNSSEC is not designed to directly protect against denial-of-service threats but does so indirectly by providing message integrity and source authentication. An artifact of how DNSSEC performs negative responses allows a client to map all the names in a zone (zone walking). 

A zone which contains zone data that the administrator does not want to be made public should use the NSEC3 RR option for providing authenticated denial of existence.

If DNSSEC is enabled for a server, the ability to verify a particular server which may attempt to update the DNS server actually exists. This is done through the use of NSEC3 records to provide an "authenticated denial of existence" for specific systems whose addresses indicate that they lie within a particular zone.)
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Review the zone configuration and confirm that, if DNSSEC is enabled NSEC3 is utilized.

Review zone data or use Global Search string ".".
Type Equals NSEC Record to verify no undesired NSEC records exists.

If NSEC records exist in an active zone, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS Properties.

Toggle Advanced Mode and edit the "DNSSEC" tab.
Ensure "Resource Record Type for Nonexistent Proof" is set to NSEC3.
Re-sign all DNSSEC zones which previously used NSEC.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15418r295872_chk'
  tag severity: 'medium'
  tag gid: 'V-214203'
  tag rid: 'SV-214203r612370_rule'
  tag stig_id: 'IDNS-7X-000720'
  tag gtitle: 'SRG-APP-000516-DNS-000084'
  tag fix_id: 'F-15416r295873_fix'
  tag 'documentable'
  tag legacy: ['SV-83091', 'V-68601']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
