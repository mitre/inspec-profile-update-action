control 'SV-254849' do
  title 'The Tanium Operating System (TanOS) must use FIPS-validated SHA-2 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.'
  desc 'To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

This requirement also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and use for compute a checksum). For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use only, but this is discouraged by DOD.

Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSH, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "X" for "Advanced Security," and then press "Enter".

If the FIPS 140-2 setting is currently disabled or persistently disabled, this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "X" for "Advanced Security," and then press "Enter".

6. Press "1" for "FIPS 140-2 mode (disabled/enabled)".

7. Type "yes" to confirm enabling FIPS 140-2 Mode and then press "Enter".

8. Press "Enter" at the confirmation prompt that instructs the user to reboot the appliance.

9. Type "RR" and press "Enter" to return to the root menu.

10. Press "B" for "Appliance Maintenance," and then press "Enter".

11. Press "B" for "Reboot/Shutdown," and then press "Enter".

12. Press "1" for "Reboot the appliance," and then press "Enter".

13. Type "Yes", and then press "Enter" to reboot the appliance and complete the configuration.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58462r866086_chk'
  tag severity: 'medium'
  tag gid: 'V-254849'
  tag rid: 'SV-254849r870369_rule'
  tag stig_id: 'TANS-OS-000385'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-58406r866087_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
