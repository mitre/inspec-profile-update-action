control 'SV-231013' do
  title 'Samsung Android must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review Samsung Android device configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool:
1. Open the device password policies.
2. Verify "minimum password quality" is set to "Numeric" (or better).
3. Verify "minimum password length" is set to "6".

NOTE: The following text is written assuming a password quality of "Numeric" or "Numeric (Complex)" has been configured. If a password quality of "Alphabetic" (or better) has been configured, substitute the text "PIN" with "Password" and "6 digits" with "6 characters".

On the Samsung Android device:
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Tap "PIN".
4. Verify the text "PIN must contain at least", followed by a value of at least "6 digits", appears above the PIN entry.

If on the management tool the "minimum password quality" is not set to "Numeric" (or better) and "minimum password length" is not set to "6", or on the Samsung Android device the text "PIN must contain at least" is followed by a value of less than "6 digits", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enforce a minimum password length of six characters.

On the management tool:
1. Open the device password policies.
2. Set "minimum password quality" to "Numeric" (or better).
3. Set "minimum password length" to "6".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33943r592653_chk'
  tag severity: 'medium'
  tag gid: 'V-231013'
  tag rid: 'SV-231013r608683_rule'
  tag stig_id: 'KNOX-11-000200'
  tag gtitle: 'PP-MDF-301010'
  tag fix_id: 'F-33916r592654_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
