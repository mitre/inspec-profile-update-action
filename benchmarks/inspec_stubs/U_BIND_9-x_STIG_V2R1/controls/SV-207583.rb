control 'SV-207583' do
  title 'On a BIND 9.x server for zones split between the external and internal sides of a network, the RRs for the external hosts must be separate from the RRs for the internal hosts.'
  desc 'Authoritative name servers for an enterprise may be configured to receive requests from both external and internal clients. 

External clients need to receive RRs that pertain only to public services (public Web server, mail server, etc.) 

Internal clients need to receive RRs pertaining to public services as well as internal hosts. 

The zone information that serves the RRs on both the inside and the outside of a firewall should be split into different physical files for these two types of clients (one file for external clients and one file for internal clients).'
  desc 'check', 'If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

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

If the internal and external view statements are configured to use the same zone file, this is a finding.

Inspect the zone file defined in the internal and external view statements.

If any resource record is listed in both the internal and external zone files, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Configure the internal and external view statements to use separate zone files.

Edit the internal and external zone files.

Configure the zone file to use RRs designated for internal or external use. The zone files should not share any RR.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7838r283803_chk'
  tag severity: 'medium'
  tag gid: 'V-207583'
  tag rid: 'SV-207583r612253_rule'
  tag stig_id: 'BIND-9X-001400'
  tag gtitle: 'SRG-APP-000516-DNS-000091'
  tag fix_id: 'F-7838r283804_fix'
  tag 'documentable'
  tag legacy: ['SV-87107', 'V-72483']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
