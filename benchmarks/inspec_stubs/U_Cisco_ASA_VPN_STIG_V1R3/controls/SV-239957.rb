control 'SV-239957' do
  title 'The Cisco ASA must be configured to use a Diffie-Hellman (DH) Group of 16 or greater for Internet Key Exchange (IKE) Phase 1.'
  desc 'Use of an approved DH algorithm ensures the IKE (Phase 1) proposal uses FIPS-validated key management techniques and processes in the production, storage, and control of private/secret cryptographic keys. The security of the DH key exchange is based on the difficulty of solving the discrete logarithm from which the key was derived. Hence, the larger the modulus, the more secure the generated key is considered to be.'
  desc 'check', 'Review the ASA configuration to determine if DH Group of 16 or greater has been specified for IKE Phase 1 as shown in the example below.

crypto ikev2 policy 1
 encryption aes-256
 …
 group 24

If DH Group of 16 or greater has not been specified for IKE Phase 1, this is a finding.'
  desc 'fix', 'Configure the ASA to use a DH Group of 16 or greater as shown in the example below.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# group 24'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43190r916129_chk'
  tag severity: 'high'
  tag gid: 'V-239957'
  tag rid: 'SV-239957r916149_rule'
  tag stig_id: 'CASA-VN-000210'
  tag gtitle: 'SRG-NET-000074-VPN-000250'
  tag fix_id: 'F-43149r916130_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
