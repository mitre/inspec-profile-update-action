control 'SV-207215' do
  title 'The site-to-site VPN, when using PKI-based authentication for devices, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to authenticate to network devices.'
  desc 'check', 'If PKI-based authentication is not being used for device authentication, this is not applicable.

Verify the site-to-site VPN that uses certificate-based device authentication uses a FIPS-compliant key management process.

If the site-to-site VPN that uses certificate-based device authentication does not use a FIPS-compliant key management process, this is a finding.'
  desc 'fix', 'Configure the site-to-site VPN that uses certificate-based device authentication to use a FIPS-compliant key management process.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7475r378266_chk'
  tag severity: 'medium'
  tag gid: 'V-207215'
  tag rid: 'SV-207215r608988_rule'
  tag stig_id: 'SRG-NET-000165-VPN-000570'
  tag gtitle: 'SRG-NET-000165'
  tag fix_id: 'F-7475r378267_fix'
  tag 'documentable'
  tag legacy: ['V-97101', 'SV-106239']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
