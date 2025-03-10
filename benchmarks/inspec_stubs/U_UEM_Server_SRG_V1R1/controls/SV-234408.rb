control 'SV-234408' do
  title 'The UEM server must generate unique session identifiers using a FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. 

The DRBGs Hash_DRBG, HMAC_DRBG, and CTR_DRBG are recommended for use with RNGs. 

This requirement is applicable to devices that use a web interface for device management. 

Satisfies:FCS_RBG_EXT.1.1, FIA_UAU.1.1, FIA_UAU.1.2'
  desc 'check', 'Verify the UEM server generates unique session identifiers using a FIPS-validated RNG based on the DRBG algorithm.

If the UEM server does not generate unique session identifiers using a FIPS-validated RNG based on the DRBG algorithm, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate unique session identifiers using a FIPS-validated RNG based on the DRBG algorithm.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37593r614234_chk'
  tag severity: 'high'
  tag gid: 'V-234408'
  tag rid: 'SV-234408r617355_rule'
  tag stig_id: 'SRG-APP-000224-UEM-000135'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-37558r614235_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
