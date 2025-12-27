control 'SV-207590' do
  title 'On the BIND 9.x server the private key corresponding to the ZSK, stored on name servers accepting dynamic updates, must be group owned by root.'
  desc 'The private ZSK key must be protected from unauthorized access.

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable.
Note: This check only verifies for ZSK key file ownership. Permissions for key files are required under V-72451, BIND-9X-001132 and V-72461, BIND-9X-001142.

For each signed zone file, identify the ZSK "key id" number:

# cat <signed_zone_file> | grep -i "zsk"
ZSK; alg = ECDSAP256SHA256; key id = 22335

Using the ZSK "key id", verify the private ZSK.

Kexample.com.+008+22335.private

Verify that the private ZSK is owned by root:

# ls -l <ZSK_key_file>
-r------- 1 root root 1776 Jul 3 17:56 Kexample.com.+008+22335.private

If the key file is not group owned by root, this is a finding.'
  desc 'fix', 'Change the group ownership of the ZSK private key to the root group account.

# chgrp root <key_file>'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7845r283824_chk'
  tag severity: 'medium'
  tag gid: 'V-207590'
  tag rid: 'SV-207590r612253_rule'
  tag stig_id: 'BIND-9X-001411'
  tag gtitle: 'SRG-APP-000516-DNS-000111'
  tag fix_id: 'F-7845r283825_fix'
  tag 'documentable'
  tag legacy: ['SV-87121', 'V-72497']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
