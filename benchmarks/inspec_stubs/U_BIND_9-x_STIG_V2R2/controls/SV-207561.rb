control 'SV-207561' do
  title 'The BIND 9.x server implementation must uniquely identify and authenticate the other DNS server before responding to a server-to-server transaction, zone transfer and/or dynamic update request using cryptographically based bidirectional authentication to protect the integrity of the information in transit.'
  desc 'Server-to-server (zone transfer) transactions are provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG), thus uniquely identifying the other server. DNS does perform server authentication when TSIG is used, but this authentication is transactional in nature (each transaction has its own authentication performed).

Enforcing mutually authenticated communication sessions during zone transfers provides the assurance that only authorized servers are requesting and receiving DNS zone data. Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Failure to properly implement transactional security may have significant effects on the overall security of the DNS infrastructure. The lack of mutual authentication between name servers during a DNS transaction would allow a threat actor to launch a Man-In-The-Middle attack against the DNS infrastructure. This attack could lead to unauthorized DNS zone data being introduced, resulting in network traffic being redirected to a rogue site.

'
  desc 'check', 'If zone transfers are disabled with the "allow-transfer { none; };" directive, this is Not Applicable.
If the server is in a classified network, this is Not Applicable.

Verify that the BIND 9.x server is configured to uniquely identify a name server before responding to a zone transfer.

Inspect the "named.conf" file for the presence of TSIG key statements:

On the master name server, this is an example of a configured key statement:

key tsig_example. {
algorithm hmac-SHA1;
include "tsig-example.key";
};

zone "disa.mil" {
type master;
file "db.disa.mil";
allow-transfer { key tsig_example.; };
};

On the slave name server, this is an example of a configured key statement:

key tsig_example. {
algorithm hmac-SHA1;
include "tsig-example.key";
};

server <ip_address> {
keys { tsig_example };
};

zone "disa.mil" {
type slave;
masters { <ip_address>; };
file "db.disa.mil";
};

If a master name server does not have a key defined in the “allow-transfer” block, this is a finding.

If a secondary name server does not have a server statement that contains a "keys" sub statement, this is a finding.'
  desc 'fix', 'Configure the BIND 9.x server to use TSIG keys.

Add a key statement to the "named.conf" file for TSIG that is being used:

key tsig_example. {
algorithm hmac-SHA1;
include "tsig-example.key";
};

Add key statements to the allow-transfer statements on a master name server:

allow-transfer { key tsig_example.; };

Add key statements to the server statements on a secondary name server:

server <ip_address> {
keys { tsig_example };
};

Restart the BIND 9.x process.'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7816r283737_chk'
  tag severity: 'high'
  tag gid: 'V-207561'
  tag rid: 'SV-207561r612253_rule'
  tag stig_id: 'BIND-9X-001100'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-7816r283738_fix'
  tag satisfies: ['SRG-APP-000158-DNS-000015', 'SRG-APP-000390-DNS-000048', 'SRG-APP-000394-DNS-000049', 'SRG-APP-000395-DNS-000050', 'SRG-APP-000439-DNS-000063', 'SRG-APP-000440-DNS-000065']
  tag 'documentable'
  tag legacy: ['SV-87053', 'V-72429']
  tag cci: ['CCI-000778', 'CCI-002421', 'CCI-001958', 'CCI-001967', 'CCI-002039', 'CCI-002418']
  tag nist: ['IA-3', 'SC-8 (1)', 'IA-3', 'IA-3 (1)', 'IA-11', 'SC-8']
end
