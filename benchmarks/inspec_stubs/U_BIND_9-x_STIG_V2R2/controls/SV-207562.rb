control 'SV-207562' do
  title 'The BIND 9.x server implementation must utilize separate TSIG key-pairs when securing server-to-server transactions.'
  desc 'Server-to-server (zone transfer) transactions are provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG), thus uniquely identifying the other server.

Enforcing separate TSIG key-pairs provides another layer of protection for the BIND implementation in the event that a TSIG key is compromised. This additional layer of security provides the DNS administrators with the ability to change a compromised TSIG key with a minimal disruption to DNS operations.

Failure to identify devices and authenticate devices can lead to malicious activity, such as a Man-In-The-Middle attack where an attacker could pose as an authorized name server, and redirect legitimate customers to malicious websites. A failure on this part could also lead to a Denial of Service of any and all DNS services provided to an organizations network infrastructure.'
  desc 'check', 'Verify that the BIND 9.x server is configured to utilize separate TSIG key-pairs when securing server-to-server transactions.
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

Verify that each TSIG key-pair listed is only used by a single key statement:
# cat <tsig_key_file>

If any TSIG key-pair is being used by more than one key statement, this is a finding.'
  desc 'fix', 'Create a separate TSIG key-pair for each key statement listed in the named.conf file.

Configure the name server to utilize separate TSIG key-pairs for each key statement listed in the named.conf file.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7817r283740_chk'
  tag severity: 'medium'
  tag gid: 'V-207562'
  tag rid: 'SV-207562r612253_rule'
  tag stig_id: 'BIND-9X-001106'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-7817r283741_fix'
  tag 'documentable'
  tag legacy: ['SV-87055', 'V-72431']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
