control 'SV-79799' do
  title 'The DataPower Gateway providing encryption intermediary services must implement NIST FIPS-validated cryptography to generate cryptographic hashes.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'From the web interface for DataPower device management, verify that the DataPower Gateway Cryptographic Mode is Set to FIPS 140-2 Level 1 (Status >> Crypto >> Cryptographic Mode Status).  

If the Mode is not set to FIPS 140-2, this is a finding.'
  desc 'fix', 'From the DataPower command line, enter "use-fips on" to configure the network device to generate unique session identifiers using a FIPS 140-2 approved random number generator. From the web interface, use "Set Cryptographic Mode" (Administration >> Miscellaneous >> Crypto Tools, Set Cryptographic Mode tab) to set the appliance to "FIPS 140-2 Level 1" mode.

This will achieve NIST SP800-131a compliance.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65309'
  tag rid: 'SV-79799r1_rule'
  tag stig_id: 'WSDP-AG-000137'
  tag gtitle: 'SRG-NET-000510-ALG-000025'
  tag fix_id: 'F-71249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
