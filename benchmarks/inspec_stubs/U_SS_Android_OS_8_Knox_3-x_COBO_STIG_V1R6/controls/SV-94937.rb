control 'SV-94937' do
  title 'Samsung Android 8 with Knox must implement the management setting: Enable CC mode.'
  desc 'CC mode implements several security controls required by the Mobile Device Functional Protection Profile (MDFPP). If CC mode is not implemented, DoD data is more at risk of being compromised, and the mobile device is more at risk of being compromised if lost or stolen. In addition., if CC Mode is not implemented, the device will not be operating in the NIAP-certified compliant CC mode of operation. 

CC mode implements the following controls:
- Enables the OpenSSL FIPS crypto library;
- Sets the password failure settings to wipe the device to "5" (5 failed consecutive attempts will wipe the device); and
- Disables ODIN mode (download mode).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing CC mode. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "CC Mode State" settings in the "Android Advanced Restrictions" rule. 
2. Verify the value is "Enabled".
3. Verify all the prerequisites have been met.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "About Device".
3. Select "Software info". (Note: On some devices, this step is not needed.)
4. Verify the value of "Security software version" does not display "Disabled".

If the MDM console "CC Mode State" is not set to "Enabled" with all prerequisites met or on the Samsung Android 8 with Knox device, "Security software version" displays "Disabled", this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce CC mode.

On the MDM console, enable the "Enable CC mode" setting in the "Android Advanced Restrictions" rule.

Note: Before applying CC policy, the CC mode state will be "Ready". Once policy is applied, the state will change to "Enabled" even if the device does not meet all the prerequisites. 

To be fully CC compliant, the Administrator must ensure all prerequisites are met.

If the device is tampered with, a self-test failed, or some other error has occurred, the state will change to "Disabled". 

Note: To fully enable CC mode, the prerequisites below should be satisfied:
1. Enable Device Encryption.
2. Enable Secure Startup.
3. Enable SD Card Encryption.
4. Set maximum Password Attempts before Wipe.
5. Enable Certificate Revocation.
6. Disable Password History.
7. Disable Face Recognition.
8. Set password "Alphanumeric".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79905r1_chk'
  tag severity: 'high'
  tag gid: 'V-80233'
  tag rid: 'SV-94937r2_rule'
  tag stig_id: 'KNOX-08-015300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87039r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
