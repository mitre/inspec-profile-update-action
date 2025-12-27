control 'SV-81137' do
  title 'The Juniper SRX Services Gateway VPN must implement a FIPS-140-2 validated Diffie-Hellman (DH) group.'
  desc 'Use of an approved DH algorithm ensures the Internet Key Exchange (IKE) (phase 1) proposal uses FIPS-validated key management techniques and processes in the production, storage, and control of private/secret cryptographic keys. The security of the DH key exchange is based on the difficulty of solving the discrete logarithm in which the key was derived from. Hence, the larger the modulus, the more secure the generated key is considered to be.'
  desc 'check', 'Verify all IKE proposals are set to use a FIPS-validated dh-group.

[edit]
show security ike <P1-PROPOSAL-NAME>

View the IKE options dh-group option.

If the IKE option is not set to a FIPS-140-2 validated dh-group, this is a finding.'
  desc 'fix', 'The following command is an example of how to configure the IKE (phase 1) proposals. The following groups are allowed for use in DoD: 
DH Groups 14 (2048-bit MODP) 
- 19 (256-bit Random ECP), 20 (384-bit Random ECP), 5 (1536-bit MODP), 24 (2048-bit MODP with 256-bit POS).

Example:
[edit]
set security ike proposal <P1-PROPOSAL-NAME> dh-group group14'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66647'
  tag rid: 'SV-81137r1_rule'
  tag stig_id: 'JUSX-VN-000007'
  tag gtitle: 'SRG-NET-000062'
  tag fix_id: 'F-72723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
