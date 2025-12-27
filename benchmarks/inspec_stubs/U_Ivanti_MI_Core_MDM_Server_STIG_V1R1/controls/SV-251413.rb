control 'SV-251413' do
  title 'The Ivanti MobileIron Core server must use FIPS-validated SHA-2 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Applications also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and use for compute a checksum). For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use only, but this is discouraged by DoD.

Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSH, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement.

'
  desc 'check', 'Verify MobileIron Core is in FIPS mode. 

ssh to command line console of the Core. Enable >> show fips. Verify FIPS mode is configured. 

If FIPS mode is not configured, this is a finding.'
  desc 'fix', 'Configure Core to be in FIPS mode.

ssh to command line console of the Core. Enable >> show fips. Configure fips >> reload.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54848r806369_chk'
  tag severity: 'high'
  tag gid: 'V-251413'
  tag rid: 'SV-251413r806371_rule'
  tag stig_id: 'IMIC-11-006400'
  tag gtitle: 'SRG-APP-000179-UEM-000110'
  tag fix_id: 'F-54801r806370_fix'
  tag satisfies: ['FCS_COP.1.1(2)']
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
