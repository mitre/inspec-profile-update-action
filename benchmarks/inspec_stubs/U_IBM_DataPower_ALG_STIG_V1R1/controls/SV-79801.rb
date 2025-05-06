control 'SV-79801' do
  title 'The DataPower Gateway providing encryption intermediary services must implement NIST FIPS-validated cryptography for digital signatures.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'From the web interface for DataPower device management, verify that the DataPower Gateway Cryptographic Mode is Set to FIPS 140-2 Level 1 (Status >> Crypto >> Cryptographic Mode Status).

If this mode is not enabled, this is a finding.

This mode bans the algorithms that are not allowed in FIPS 140-2 Level 1. The banned algorithms include Blowfish, CAST, DES, MD2, MD4, MD5, RC2, RC4, and RIPEMD. This mode also bans RSA keys less than 1024 bits and disables the cryptographic hardware that is not FIPS validated.'
  desc 'fix', 'The privileged user will apply the following tasks: 

From the DataPower command line, enter "use-fips on" to configure the network device to generate unique session identifiers using a FIPS 140-2 approved random number generator. From the web interface, in the default domain, use "Set Cryptographic Mode" (Administration >> Miscellaneous >> Crypto Tools, Set Cryptographic Mode tab) to set the appliance to "FIPS 140-2 Level 1" mode.

The privileged use will add a Verify action to the appropriate processing policy in the application domain (non-default domain). This action will check that only NIST SP800-131a approved digital signatures will be used.

This will achieve NIST SP800-131a compliance.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65939r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65311'
  tag rid: 'SV-79801r1_rule'
  tag stig_id: 'WSDP-AG-000138'
  tag gtitle: 'SRG-NET-000510-ALG-000040'
  tag fix_id: 'F-71251r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
