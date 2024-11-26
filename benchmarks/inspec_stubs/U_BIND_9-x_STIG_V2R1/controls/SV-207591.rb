control 'SV-207591' do
  title 'A BIND 9.x server implementation must enforce approved authorizations for controlling the flow of information between authoritative name servers and specified secondary name servers based on DNSSEC policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Within the context of DNS, this is applicable in terms of controlling the flow of DNS information between systems, such as DNS zone transfers.

Authoritative name servers (especially primary name servers) should be configured with an allow-transfer access control sub statement designating the list of hosts from which DNS information, such as zone transfers, can be accepted. These restrictions address the denial-of-service threat and potential exploits from unrestricted dissemination of information about internal resources.

Zone transfer from primary name servers should be restricted to secondary name servers. The zone transfer should be completely disabled in the secondary name servers. The address match list argument for the allow-transfer sub statement should consist of IP addresses of secondary name servers and stealth secondary name servers.

'
  desc 'check', 'On an authoritative name sever, verify that each zone statement defined in the "named.conf" file contains an "allow-transfer" statement.

Inspect the "named.conf" file for the following:

zone example.com {
allow-transfer { <ip_address_list>; };
};

If there is not an "allow-transfer" statement for each zone defined, or the list contains IP addresses that are not authorized for that zone, this is a finding.

On a slave name server, verify that each zone statement defined in the "named.conf" file contains an "allow-transfer" statement.

Inspect the "named.conf" file for the following:

zone example.com {
allow-transfer { none; };
};

If there is not an "allow-transfer" statement, or the statement is not set to "none", this is a finding.'
  desc 'fix', 'For an authoritative name server:

Configure each zone statement to allow transfers from authorized hosts:

allow-transfer { <ip_address_list>; };

Restart the BIND 9.x process.

For a secondary server:

Configure each zone to deny zone transfer requests:

allow-transfer { none; };

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7846r283827_chk'
  tag severity: 'medium'
  tag gid: 'V-207591'
  tag rid: 'SV-207591r612253_rule'
  tag stig_id: 'BIND-9X-001510'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-7846r283828_fix'
  tag satisfies: ['SRG-APP-000215-DNS-000003', 'SRG-APP-000516-DNS-000095']
  tag 'documentable'
  tag legacy: ['SV-87123', 'V-72499']
  tag cci: ['CCI-000366', 'CCI-001663']
  tag nist: ['CM-6 b', 'SC-20 b']
end
