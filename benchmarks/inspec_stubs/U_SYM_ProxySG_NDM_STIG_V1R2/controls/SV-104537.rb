control 'SV-104537' do
  title 'Symantec ProxySG must be configured to use only FIPS 140-2 approved algorithms for authentication to a cryptographic module with any application or protocol.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

The Symantec ProxySG can be configured in FIPS-mode, but this is not recommended by the vendor or DoD. Instead, ensure that FIPS-compliant mechanisms are used for authenticating to cryptographic modules when not in FIPS-mode. This is true by default, but must be verified to prevent misconfiguration by an administrator.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Applications also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and using SHA-1 or higher to compute a checksum). For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use where needed.

Currently, the AES block cipher algorithm is approved for use in DoD for both applying cryptographic protection (e.g., encryption) and removing or verifying the protection that was previously applied (e.g., decryption). NTP devices use MD5 authentication keys. The MD5 algorithm is not specified in either the FIPS or NIST recommendation; thus, a CAT 1 finding if used. However, MD5 is preferred to no authentication at all.'
  desc 'check', 'Verify only FIPS 140-2 approved algorithms are used.

1. Log on to the CLI via SSH.
2. Type "show management services", press "Enter".
3. Ensure that the "Cipher Suite" attribute contains only FIPS 140-2 approved algorithms.

If Symantec ProxySG is not configured to use FIPS 140-2 approved algorithms for authentication to a cryptographic module for any protocol or application, this is a finding.'
  desc 'fix', 'Configure the ProxySG to use only FIPS 140-2 approved algorithms.

1. Log on to the CLI via SSH.
2. Type "enable", press "Enter". 
3. Type "configure", press "Enter".
4. Type "management services", press "Enter".
5. Type "edit https-console", press "Enter".
6. Type "attribute cipher-suite", press "Enter".
7. From the list displayed, enter a list of cipher numbers (comma separated) that correspond to only FIPS 140-2 approved algorithms.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93897r1_chk'
  tag severity: 'high'
  tag gid: 'V-94707'
  tag rid: 'SV-104537r1_rule'
  tag stig_id: 'SYMP-NM-000280'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-100825r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
