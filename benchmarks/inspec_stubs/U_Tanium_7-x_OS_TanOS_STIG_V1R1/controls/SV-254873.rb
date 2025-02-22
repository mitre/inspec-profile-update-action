control 'SV-254873' do
  title 'The Tanium Operating System (TanOS) must use a FIPS-validated cryptographic module to provision digital signatures.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within federal systems. Un-validated cryptography is viewed by NIST as providing no protection to the information or data - in effect the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, then it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard. 

The cryptographic module used must have at least one validated digital signature function. This validated hash algorithm must be used to generate digital signatures for all cryptographic security function within the product being evaluated.

'
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

7. Type "yes" to confirm enabling FIPS 140-2 Mode, and then press "Enter".

8. Press "Enter" at the confirmation prompt that instructs the user to reboot the appliance.

9. Type "RR" and press "Enter" to return to the root menu.

10. Press "B" for "Appliance Maintenance," and then press "Enter".

11. Press "B" for "Reboot/Shutdown," and then press "Enter".

12. Press "1" for "Reboot the appliance," and then press "Enter".

13. Type "Yes" and then press "Enter" to reboot the appliance and complete the configuration.'
  impact 0.7
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58486r866158_chk'
  tag severity: 'high'
  tag gid: 'V-254873'
  tag rid: 'SV-254873r866160_rule'
  tag stig_id: 'TANS-OS-001760'
  tag gtitle: 'SRG-OS-000550'
  tag fix_id: 'F-58430r866159_fix'
  tag satisfies: ['SRG-OS-000550', 'SRG-OS-000530']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-002450']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-13 b']
end
