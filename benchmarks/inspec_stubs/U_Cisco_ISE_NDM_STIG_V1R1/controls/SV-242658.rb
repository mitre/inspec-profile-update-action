control 'SV-242658' do
  title 'The Cisco ISE must generate unique session identifiers using a FIPS 140-2 approved Random Number Generator (RNG) using DRGB.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. SP 800-131A makes clear that RNGs specified in FIPS 186-2, ANS X9.31-1998 and ANS X9.62-1998 will be disallowed after 2015. Only SP 800-90A based random number generators will continue to be approved. NIST SP 800-90A- Recommendation for Random Number Generation using Deterministic Random Bit Generators was published in January 2012.

This requirement is applicable to devices that use a web interface for device management.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If the Cisco ISE does not generate unique session identifiers using a FIPS 140-2 approved RNG, this is a finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure DRBG is used for all RNG functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45933r714282_chk'
  tag severity: 'medium'
  tag gid: 'V-242658'
  tag rid: 'SV-242658r714284_rule'
  tag stig_id: 'CSCO-NM-000530'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-45890r714283_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
