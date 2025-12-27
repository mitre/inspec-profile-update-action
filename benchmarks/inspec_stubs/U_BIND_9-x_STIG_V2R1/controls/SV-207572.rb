control 'SV-207572' do
  title 'On the BIND 9.x server the private keys corresponding to both the ZSK and the KSK must not be kept on the BIND 9.x DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets. The private key corresponding to the key-signing key (KSK-private) can still be kept off-line.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

Determine if the BIND 9.x server is configured to allow dynamic updates.

Review the "named.conf" file for any instance of the "allow-update" statement. The following example disables dynamic updates:

allow-update {none;};

If the BIND 9.x implementation is not configured to allow dynamic updates, verify with the SA that the private ZSKs and private KSKs are stored offline, if not, this is a finding.'
  desc 'fix', 'Remove any ZSK or KSK private key from any BIND 9.x server that does not support dynamic updates.

Note: Any ZSK or KSK that is not needed to support dynamic updates should be stored offline in a secure location.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7827r283770_chk'
  tag severity: 'medium'
  tag gid: 'V-207572'
  tag rid: 'SV-207572r612253_rule'
  tag stig_id: 'BIND-9X-001134'
  tag gtitle: 'SRG-APP-000516-DNS-000112'
  tag fix_id: 'F-7827r283771_fix'
  tag 'documentable'
  tag legacy: ['SV-87079', 'V-72455']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
