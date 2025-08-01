control 'SV-207596' do
  title 'On a BIND 9.x server all authoritative name servers for a zone must have the same version of zone information.'
  desc 'It is important to maintain the integrity of a zone file. The serial number of the SOA record is used to indicate to secondary name server that a change to the zone has occurred and a zone transfer should be performed. The serial number used in the SOA record provides the DNS administrator a method to verify the integrity of the zone file based on the serial number of the last update and ensure that all slave servers are using the correct zone file.'
  desc 'check', 'Verify that the SOA record is at the same version for all authoritative servers for a specific zone.

With the assistance of the DNS administrator, identify each name server that is authoritative for each zone.

Inspect each zone file that the server is authoritative for and identify the following:

example.com. 86400 IN SOA ns1.example.com. root.example.com. (17760704;serial) 

If the SOA "serial" numbers are not identical on each authoritative name server, this is a finding.'
  desc 'fix', 'Edit the zone file.

Update the SOA record serial number.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7851r283842_chk'
  tag severity: 'medium'
  tag gid: 'V-207596'
  tag rid: 'SV-207596r612253_rule'
  tag stig_id: 'BIND-9X-001613'
  tag gtitle: 'SRG-APP-000516-DNS-000088'
  tag fix_id: 'F-7851r283843_fix'
  tag 'documentable'
  tag legacy: ['SV-87133', 'V-72509']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
