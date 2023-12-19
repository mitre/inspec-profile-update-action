control 'SV-207595' do
  title 'On a BIND 9.x server all authoritative name servers for a zone must be located on different network segments.'
  desc 'Most enterprises have an authoritative primary server and a host of authoritative secondary name servers. It is essential that these authoritative name servers for an enterprise be located on different network segments. This dispersion ensures the availability of an authoritative name server not only in situations in which a particular router or switch fails but also during events involving an attack on an entire network segment.'
  desc 'check', 'Verify that each name server listed on the BIND 9.x server is on a separate network segment.

Inspect the "named.conf" file and identify all of the zone files that the BIND 9.x server is using.

zone "example.com" {
file "zone_file";
};

Inspect each zone file and identify each A record for each NS record listed:

ns1.example.com 86400 IN A 192.168.1.4
ns2.example.com 86400 IN A 192.168.2.4

If there are name servers listed in the zone file that are not on different network segments for the specified domain, this is a finding.'
  desc 'fix', 'Edit the zone file and configure each name server on a separate network segment.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7850r283839_chk'
  tag severity: 'medium'
  tag gid: 'V-207595'
  tag rid: 'SV-207595r612253_rule'
  tag stig_id: 'BIND-9X-001612'
  tag gtitle: 'SRG-APP-000516-DNS-000087'
  tag fix_id: 'F-7850r283840_fix'
  tag 'documentable'
  tag legacy: ['SV-87131', 'V-72507']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
