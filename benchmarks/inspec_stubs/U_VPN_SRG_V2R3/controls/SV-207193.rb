control 'SV-207193' do
  title 'The IPsec VPN must implement a FIPS 140-2 validated Diffie-Hellman (DH) group.'
  desc 'Use of an approved DH algorithm ensures the Internet Key Exchange (IKE) (phase 1) proposal uses FIPS-validated key management techniques and processes in the production, storage, and control of private/secret cryptographic keys. The security of the DH key exchange is based on the difficulty of solving the discrete logarithm in which the key was derived from. Hence, the larger the modulus, the more secure the generated key is considered to be.'
  desc 'check', 'Verify all IKE proposals are set to use a FIPS-validated dh-group.

View the IKE options dh-group option.

If the IKE option is not set to a FIPS 140-2 validated dh-group, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN to us the FIPS 140-2 DH group. The following command is an example of how to configure the IKE (phase 1) proposals. 

The following groups are allowed for use in DoD: 
DH Groups 14 (2048-bit MODP) 
- 19 (256-bit Random ECP), 20 (384-bit Random ECP), 5 (1536-bit MODP), 24 (2048-bit MODP with 256-bit POS).'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7453r378200_chk'
  tag severity: 'high'
  tag gid: 'V-207193'
  tag rid: 'SV-207193r608988_rule'
  tag stig_id: 'SRG-NET-000074-VPN-000250'
  tag gtitle: 'SRG-NET-000074'
  tag fix_id: 'F-7453r378201_fix'
  tag 'documentable'
  tag legacy: ['SV-106197', 'V-97059']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
