control 'SV-242653' do
  title 'The Cisco ISE must use FIPS-validated SHA-2 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. 

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Applications also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and use for compute a checksum). For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use only, but this is discouraged by DoD.

Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSH, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If the Cisco ISE does not generate unique session identifiers using a FIPS 140-2 approved RNG, this is a finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure DRBG is used for all RNG functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45928r714267_chk'
  tag severity: 'high'
  tag gid: 'V-242653'
  tag rid: 'SV-242653r714269_rule'
  tag stig_id: 'CSCO-NM-000480'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-45885r714268_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
