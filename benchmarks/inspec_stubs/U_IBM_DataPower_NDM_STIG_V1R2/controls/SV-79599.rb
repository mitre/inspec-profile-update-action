control 'SV-79599' do
  title 'The DataPower Gateway must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement is applicable to devices that use a web interface for device management.'
  desc 'check', 'From the web interface for DataPower device management, verify that the DataPower Gateway Cryptographic Mode is Set to FIPS 140-2 Level 1; Status >> Crypto >> Cryptographic Mode Status.

If it is not set to FIPS 140-2, this is a finding.

Then, verify that the session identifiers (TIDs) in the System Log are random: Status >> View Logs >> Systems Logs.

If they are not random, this is a finding.'
  desc 'fix', 'From the DataPower command line, enter "use-fips on" to configure DataPower to generate unique session identifiers using a FIPS 140-2 approved random number generator. From the web interface, use "Set Cryptographic Mode" (Administration >> Miscellaneous >> Crypto Tools, Set Cryptographic Mode tab) to set the appliance to "FIPS 140-2 Level 1" mode.

This will achieve NIST SP800-131a compliance.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65737r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65109'
  tag rid: 'SV-79599r1_rule'
  tag stig_id: 'WSDP-NM-000072'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-71049r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
