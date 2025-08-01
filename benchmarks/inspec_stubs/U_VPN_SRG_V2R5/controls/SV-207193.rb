control 'SV-207193' do
  title 'The IPSec VPN must be configured to use a Diffie-Hellman (DH) Group of 16 or greater for Internet Key Exchange (IKE) Phase 1.'
  desc 'Use of an approved DH algorithm ensures the IKE (Phase 1) proposal uses FIPS-validated key management techniques and processes in the production, storage, and control of private/secret cryptographic keys. The security of the DH key exchange is based on the difficulty of solving the discrete logarithm from which the key was derived. Hence, the larger the modulus, the more secure the generated key is considered to be.'
  desc 'check', 'Verify all IKE proposals are set to use DH Group of 16 or greater for IKE Phase 1.

View the IKE options dh-group option.

If the IKE option is not set to use DH Group of 16 or greater for IKE Phase 1, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN to use the DH Group of 16 or greater for IKE Phase 1.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7453r916147_chk'
  tag severity: 'high'
  tag gid: 'V-207193'
  tag rid: 'SV-207193r916149_rule'
  tag stig_id: 'SRG-NET-000074-VPN-000250'
  tag gtitle: 'SRG-NET-000074'
  tag fix_id: 'F-7453r916148_fix'
  tag 'documentable'
  tag legacy: ['SV-106197', 'V-97059']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
