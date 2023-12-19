control 'SV-207594' do
  title 'Every NS record in a zone file on a BIND 9.x server must point to an active name server and that name server must be authoritative for the domain specified in that record.'
  desc "Poorly constructed NS records pose a security risk because they create conditions under which an adversary might be able to provide the missing authoritative name services that are improperly specified in the zone file. The adversary could issue bogus responses to queries that clients would accept because they learned of the adversary's name server from a valid authoritative name server, one that need not be compromised for this attack to be successful. The list of slave servers must remain current within 72 hours of any changes to the zone architecture that would affect the list of slaves. If a slave server has been retired or is not operational but remains on the list, then an adversary might have a greater opportunity to impersonate that slave without detection, rather than if the slave were actually online. For example, the adversary may be able to spoof the retired slave's IP address without an IP address conflict, which would not be likely to occur if the true slave were active."
  desc 'check', 'Verify that each name server listed on the BIND 9.x server is authoritative for the domain it supports.

Inspect the "named.conf" file and identify all of the zone files that the BIND 9.x server is using.

zone "example.com" {
file "zone_file";
};

Inspect each zone file and identify each NS record listed.

86400 NS ns1.example.com
86400 NS ns2.example.com

With the assistance of the DNS Administrator, verify that each name server listed is authoritative for that domain.

If there are name servers listed in the zone file that are not authoritative for the specified domain, this is a finding.'
  desc 'fix', 'Edit the zone file(s).

Remove any name server that the BIND 9.x server is not authoritative for.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7849r283836_chk'
  tag severity: 'medium'
  tag gid: 'V-207594'
  tag rid: 'SV-207594r612253_rule'
  tag stig_id: 'BIND-9X-001611'
  tag gtitle: 'SRG-APP-000516-DNS-000085'
  tag fix_id: 'F-7849r283837_fix'
  tag 'documentable'
  tag legacy: ['SV-87129', 'V-72505']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
