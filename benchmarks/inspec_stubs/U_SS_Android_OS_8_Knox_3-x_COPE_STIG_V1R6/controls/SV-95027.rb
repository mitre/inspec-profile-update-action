control 'SV-95027' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure minimum password complexity.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. A minimum level of complexity is needed to ensure a simple password or easily guessed password is not used.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has been configured with a minimum password complexity.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following: 
1. Ask the MDM Administrator to display the "Minimum Password Complexity" setting in the "Android Restrictions" rule. 
2. Verify the setting is "PIN" (see note).

On the Samsung Android 8 with Knox device, do the following: 
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Screen lock type".
4. Verify "Swipe", "Pattern", and, "None" are disabled (grayed out) and cannot be enabled.

If the MDM console "Minimum Password Complexity" is not configured to "PIN" or on the Samsung Android 8 with Knox device, the user can enable the setting, this is a finding.

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to have a minimum password complexity.

On the MDM console, configure "Minimum Password Complexity" to "PIN" in the "Android Password Restrictions" rule.  

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79995r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80323'
  tag rid: 'SV-95027r2_rule'
  tag stig_id: 'KNOX-08-008800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87129r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
