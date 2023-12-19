control 'SV-69175' do
  title 'All authoritative name servers for a zone must have the same version of zone information.'
  desc 'The only protection approach for content control of DNS zone file is the use of a zone file integrity checker. The effectiveness of integrity checking using a zone file integrity checker depends upon the database of constraints built into the checker. The deployment process consists of developing these constraints with the right logic, and the only determinant of the truth value of these logical predicates is the parameter values for certain key fields in the format of various RRTypes.

The serial number in the SOA RDATA is used to indicate to secondary name servers that a change to the zone has occurred and a zone transfer should be performed. It should always be increased whenever a change is made to the zone data. DNS NOTIFY must be enabled on the master authoritative name server.'
  desc 'check', 'Review the DNS configuration for each zone hosted by the authoritative name server. Determine all authoritative name servers for each zone. Review the serial number in the SOA RDATA, on each authoritative name server for each zone, and ensure the serial number is the same on each secondary name server as on the primary name server.

If any secondary name server for a zone has a serial number in the SOA RDATA that is different from the primary name server, this is a finding.'
  desc 'fix', 'Troubleshoot and fix any problems with zone transfers completing successfully between the primary name server and all secondary name servers.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55555r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54929'
  tag rid: 'SV-69175r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000088'
  tag gtitle: 'SRG-APP-000516-DNS-000088'
  tag fix_id: 'F-59791r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
