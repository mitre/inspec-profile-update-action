control 'SV-207553' do
  title 'A BIND 9.x server implementation must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'A DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

A denial of service (DoS) attack against the DNS infrastructure has the potential to cause a DoS to all network users. As the DNS is a distributed backbone service of the Internet, various forms of amplification attacks resulting in DoS, while utilizing the DNS, are still prevalent on the Internet today. Some potential DoS flooding attacks against the DNS include malformed packet flood, spoofed source addresses, and distributed DoS. Without the DNS, users and systems would not have the ability to perform simple name to IP resolution. 

Configuring the DNS implementation to defend against cache poisoning, employing increased capacity and bandwidth, building redundancy into the DNS architecture, utilizing DNSSEC, limiting and securing recursive services, DNS black holes, etc., may reduce the susceptibility to some flooding types of DoS attacks.'
  desc 'check', 'If this is a recursive name server, this is not applicable.

Note: A recursive name server should NOT be configured as an authoritative name server for any zone.

Verify that the BIND 9.x server is configured to prohibit recursion on authoritative name servers.

Inspect the "named.conf" file for the following:

options {
recursion no;
allow-query {none;};
};

If the "recursion" sub statement is missing, or set to "yes", this is a finding.

If the "allow-query" sub statement under the "options statement" is not set to "none", this is a finding.

Verify that an "allow-query" sub statement under each zone statement is configured to authorized hosts:

zone "example.com" {
type master;
file "db.example.com";
allow-query { (address_match_list | <ip_address>) };
};

If the "allow-query" sub statement under each zone statement is not restricted to authorized hosts, this is a finding.'
  desc 'fix', 'Configure the authoritative name server to prohibit recursion.

Edit the "named.conf" file and add the following sub statements to the options statement:

recursion no;
allow-query { none };

Configure each zone to limit queries to authorized hosts:

Edit the "named.conf" file and add the following sub statement to each zone definition:

allow-query { address_match_list; };

Restart the BIND 9.x process'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7808r283713_chk'
  tag severity: 'medium'
  tag gid: 'V-207553'
  tag rid: 'SV-207553r612253_rule'
  tag stig_id: 'BIND-9X-001054'
  tag gtitle: 'SRG-APP-000247-DNS-000036'
  tag fix_id: 'F-7808r283714_fix'
  tag 'documentable'
  tag legacy: ['SV-87029', 'V-72405']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
