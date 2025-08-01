control 'SV-79727' do
  title 'The DataPower Gateway must recognize only system-generated session identifiers.'
  desc "Network elements (depending on function) utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier, or can inject or manually insert session information, the valid user's application session can be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement focuses on communications protection for the application session rather than for the network packet."
  desc 'check', 'From the web interface for DataPower device management, verify that the DataPower Gateway Cryptographic Mode is Set to FIPS 140-2 Level 1; Status >> Crypto >> Cryptographic Mode Status 

Then, verify that the session identifiers (TIDs) in the System Log are random; Status >> View Logs >> Systems Logs.

If these items are not configured, this is a finding.'
  desc 'fix', 'From the DataPower command line, enter "use-fips on" to configure DataPower to generate unique session identifiers using a FIPS 140-2 approved random number generator. From the web interface, use "Set Cryptographic Mode" (Administration >> Miscellaneous >> Crypto Tools, Set Cryptographic Mode tab) to set the appliance to "FIPS 140-2 Level 1" mode.

This will achieve NIST SP800-131a compliance.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65237'
  tag rid: 'SV-79727r1_rule'
  tag stig_id: 'WSDP-AG-000051'
  tag gtitle: 'SRG-NET-000233-ALG-000115'
  tag fix_id: 'F-71177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
