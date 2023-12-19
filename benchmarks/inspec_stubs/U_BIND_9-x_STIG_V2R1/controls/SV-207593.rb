control 'SV-207593' do
  title 'A BIND 9.x server NSEC3 must be used for all internal DNS zones.'
  desc 'To ensure that RRs associated with a query are really missing in a zone file and have not been removed in transit, the DNSSEC mechanism provides a means for authenticating the nonexistence of an RR. It generates a special RR called an NSEC (or NSEC3) RR that lists the RRTypes associated with an owner name as well as the next name in the zone file. It sends this special RR, along with its signatures, to the resolving name server. By verifying the signature, a DNSSEC-aware resolving name server can determine which authoritative owner name exists in a zone and which authoritative RRTypes exist at those owner names.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable. If the server is on an internal, restricted network with reserved IP space, this is Not Applicable.


With the assistance of the DNS Administrator, identify each internal DNS zone listed in the "named.conf" file.

For each internal zone identified, inspect the signed zone file for the NSEC resource records:

86400 NSEC example.com. A RRSIG NSEC

If the zone file does not contain an NSEC record for the zone, this is a finding.'
  desc 'fix', 'Resign each zone that is missing NSEC records.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7848r283833_chk'
  tag severity: 'medium'
  tag gid: 'V-207593'
  tag rid: 'SV-207593r612253_rule'
  tag stig_id: 'BIND-9X-001610'
  tag gtitle: 'SRG-APP-000516-DNS-000084'
  tag fix_id: 'F-7848r283834_fix'
  tag 'documentable'
  tag legacy: ['SV-87127', 'V-72503']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
