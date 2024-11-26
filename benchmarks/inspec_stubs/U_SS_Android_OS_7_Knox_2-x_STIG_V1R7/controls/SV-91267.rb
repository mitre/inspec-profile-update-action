control 'SV-91267' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Enable CC mode.'
  desc 'CC mode implements several security controls required by the Mobile Device Functional Protection Profile (MDFPP). If CC mode is not implemented, DoD data is more at risk of being compromised, and the mobile device is more at risk of being compromised if lost or stolen. If CC Mode is not implemented, the device will not be operating in the NIAP-certified compliant CC mode of operation. 

CC mode implements the following controls:
- enables the OpenSSL FIPS crypto library
- sets the password failure settings to wipe the device to 5 (5 failed consecutive attempts will wipe the device)
- disables ODIN mode (download mode)

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing CC mode. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "CC Mode State" settings in the "Android Advanced Restrictions" rule. 
2. Verify the value is enabled.

Note: If the MDM does not support CC mode, ask the MDM administrator if the Samsung APK has been installed and CC mode enabled.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "About Device".
3. Select "Software info". (Note: On some devices, this step is not needed.)
4. Verify the value of "Security software version" displays "Enabled".

If the MDM console "CC Mode State" is not set to "Enabled" or on the Samsung Android 7 with Knox device, "Security software version" does not display "Enabled", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce CC mode.

On the MDM console, enable the "Enable CC mode" setting in the "Android Advanced Restrictions" rule.

If this setting is not available on the console, install the CC mode APK and enable CC mode from this application.

This APK will be made available by Samsung.

Note: Before applying CC policy, the CC mode state will be "Ready". Once policy is applied, the state will change to "Enforced" until device meets all the prerequisites. 

If device meets all prerequisites, CC mode will be enabled after rebooting and state will change to "Enabled".

If the device is tampered or FIPS self-test is failed, the state will change to "Disabled". 

Note: To fully enable CC mode, below prerequisites should be satisfied:
1. Enable Device Encryption
2. Enable SD Card Encryption
3. Set maximum Password Attempts before Wipe
4. Enable Certificate Revocation
5. Disable Password History'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76237r1_chk'
  tag severity: 'high'
  tag gid: 'V-76571'
  tag rid: 'SV-91267r2_rule'
  tag stig_id: 'KNOX-07-012100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83265r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
