control 'SV-254853' do
  title 'The Tanium Operating System (TanOS) must use FIPS-validated encryption and hashing algorithms to protect the confidentiality and integrity of operating system configuration and user-generated data stored on the host.'
  desc 'Confidentiality and integrity protections are intended to address the confidentiality and integrity of system information at rest when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

This requirement addresses the protection of user-generated data as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
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

6. Press "1" for "FIPS 140-2 mode (disabled/enabled).

7. Type "yes" to confirm enabling FIPS 140-2 Mode, and then press "Enter".

8. Press "Enter" at the confirmation prompt that instructs the user to reboot the appliance.

9. Type "RR" and press "Enter" to return to the root menu.

10. Press "B" for "Appliance Maintenance," and then press "Enter".

11. Press "B" for "Reboot/Shutdown," and then press "Enter".

12. Press "1" for "Reboot the appliance," and then press "Enter".

13. Type "Yes" and press "Enter" to reboot the appliance and complete the configuration.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58466r866098_chk'
  tag severity: 'medium'
  tag gid: 'V-254853'
  tag rid: 'SV-254853r866100_rule'
  tag stig_id: 'TANS-OS-000515'
  tag gtitle: 'SRG-OS-000185'
  tag fix_id: 'F-58410r866099_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
