control 'SV-207586' do
  title 'A BIND 9.x server implementation must implement internal/external role separation.'
  desc 'DNS servers with an internal role only process name/address resolution requests from within the organization (i.e., internal clients). DNS servers with an external role only process name/address resolution information requests from clients external to the organization (i.e., on the external networks, including the Internet). The set of clients that can access an authoritative DNS server in a particular role is specified by the organization using address ranges, explicit access control lists, etc. In order to protect internal DNS resource information, it is important to isolate the requests to internal DNS servers. 

Failure to separate internal and external roles in DNS may lead to address space that is private (e.g., 10.0.0.0/24) or is otherwise concealed by some form of Network Address Translation from leaking into the public DNS system. Allowing private IP space to leak into the public DNS system may provide a person with malicious intent the ability to footprint your network and identify potential attack targets residing on your private network.'
  desc 'check', 'Severity Override Guidance:
If the internal and external views are on separate network segments, this finding may be downgraded to a CAT II.

If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the BIND 9.x server is configured to use separate views and address space for internal and external DNS operations when operating in a split configuration.

Inspect the "named.conf" file for the following:

view "internal" {
match-clients { <ip_address> | <address_match_list> };
zone "example.com" {
type master;
file "internals.example.com";
};
};
view "external" {
match-clients { <ip_address> | <address_match_list> };
zone "example.com" {
type master;
file "externals.db.example.com";
allow-transfer { slaves; };
};
};

If an external view is listed before an internal view, this is a finding.

If the internal and external views are on the same network segment, this is a finding.

Note: BIND 9.x reads the "named.conf" file from top to bottom. If a less stringent "match-clients" statement is processed before a more stringent "match-clients" statement, the more stringent statement will be ignored. With this in mind, all internal view statements should be listed before any external view statement in the "named.conf" file.'
  desc 'fix', 'Edit the "named.conf" file.

Configure the internal and external view statements to use separate network segments.

Configure all internal view statements to be listed before any external view statement.

Restart the BIND 9.x process.'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7841r283812_chk'
  tag severity: 'high'
  tag gid: 'V-207586'
  tag rid: 'SV-207586r612253_rule'
  tag stig_id: 'BIND-9X-001403'
  tag gtitle: 'SRG-APP-000516-DNS-000101'
  tag fix_id: 'F-7841r283813_fix'
  tag 'documentable'
  tag legacy: ['V-72489', 'SV-87113']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
