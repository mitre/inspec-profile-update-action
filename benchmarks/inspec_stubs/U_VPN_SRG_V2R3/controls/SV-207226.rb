control 'SV-207226' do
  title 'The VPN Gateway must generate unique session identifiers using FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm.'
  desc 'Both IPsec and TLS gateways use the RNG to strengthen the security of the protocols. Using a weak RNG will weaken the protocol and make it more vulnerable.

Use of a FIPS validated RNG that is not DRGB mitigates to a CAT III.'
  desc 'check', 'Verify the VPN Gateway generates unique session identifiers using FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm.

If the VPN Gateway does not generate unique session identifiers using FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate unique session identifiers using FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7486r378299_chk'
  tag severity: 'medium'
  tag gid: 'V-207226'
  tag rid: 'SV-207226r608988_rule'
  tag stig_id: 'SRG-NET-000234-VPN-000810'
  tag gtitle: 'SRG-NET-000234'
  tag fix_id: 'F-7486r378300_fix'
  tag 'documentable'
  tag legacy: ['V-97131', 'SV-106269']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
