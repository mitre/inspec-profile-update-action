control 'SV-207587' do
  title 'On the BIND 9.x server the IP address for hidden master authoritative name servers must not appear in the name servers set in the zone database.'
  desc 'A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. All of the name servers that do appear in the zone database as designated name servers get their zone data from the hidden master via a zone transfer request. In effect, all visible name servers are actually secondary slave servers. This prevents potential attackers from targeting the master name server because its IP address may not appear in the zone database.'
  desc 'check', 'If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

With the assistance of the DNS administrator, identify if the BIND 9.x implementation is using a hidden master name server, if it is not, this is Not Applicable.

In a split DNS configuration that is using a hidden master name server, verify that the name server IP address is not listed in the zone file.

With the assistance of the DNS administrator, obtain the IP address of the hidden master name server.

Inspect each zone file used by the hidden master name server and its slave zones.

If the IP address for the hidden master name server is listed in any of the zone files, this is a finding.'
  desc 'fix', 'Edit the zone file(s).

Remove all references to the hidden master name server.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7842r283815_chk'
  tag severity: 'medium'
  tag gid: 'V-207587'
  tag rid: 'SV-207587r612253_rule'
  tag stig_id: 'BIND-9X-001404'
  tag gtitle: 'SRG-APP-000516-DNS-000108'
  tag fix_id: 'F-7842r283816_fix'
  tag 'documentable'
  tag legacy: ['SV-87115', 'V-72491']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
