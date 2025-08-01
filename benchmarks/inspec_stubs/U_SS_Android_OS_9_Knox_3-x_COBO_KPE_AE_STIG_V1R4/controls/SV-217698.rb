control 'SV-217698' do
  title 'Samsung Android must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks. 

Setting a lock type enables a screen-lock policy, and each lock type has a password strength. Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. A minimum level of complexity is needed to ensure a simple password or easily guessed password is not used. 

Configuring a minimum password complexity mitigates both the risk associated with an adversary acquiring a device in an unlocked state and a screen lock type with a weak authentication factor.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review device configuration settings to confirm that the device uses a screen-lock policy that will lock the display after a period of inactivity and that the lock type is configured with a minimum password quality. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android password constraints" group, verify that the "minimum password quality" is "PIN" (see note).

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Tap "Screen lock type". 
4. Verify that "Swipe”, “Pattern:, and “None" cannot be enabled. 

If on the MDM console "minimum password quality" is not set to "PIN", or on the Samsung Android device the user can select a screen lock type other than "password", this is a finding.

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”.  Either selection is acceptable but “Numeric-Complex” is recommended.  Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure Samsung Android to enforce a screen-lock policy that will lock the display after a period of inactivity, with a lock type that is configured with a minimum password quality. 

On the MDM console, for the device, in the "Android password constraints" group, set "minimum password quality" (or password type) to "PIN".

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”.  Either selection is acceptable but “Numeric-Complex” is recommended.  Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18917r362123_chk'
  tag severity: 'medium'
  tag gid: 'V-217698'
  tag rid: 'SV-217698r378598_rule'
  tag stig_id: 'KNOX-09-001440'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-18915r362124_fix'
  tag 'documentable'
  tag legacy: ['SV-103021', 'V-92933']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
