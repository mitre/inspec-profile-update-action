control 'SV-251807' do
  title 'Samsung Android must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enforcing a minimum password length of six characters.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device password policies, verify "minimum password length" is set to "6".

On the Samsung Android device:
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Tap "PIN".
4. Verify the text "PIN must contain at least", followed by a value of at least "6 digits", appears above the PIN entry.

If on the management tool "minimum password length" is not set to "6", or on the Samsung Android device the text "PIN must contain at least" is followed by a value of less than "6 digits", this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enforce a minimum password length of six characters.

On the management tool, in the device password policies, set "minimum password length" to "6".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55267r814175_chk'
  tag severity: 'medium'
  tag gid: 'V-251807'
  tag rid: 'SV-251807r814177_rule'
  tag stig_id: 'KNOX-12-110050'
  tag gtitle: 'PP-MDF-323000'
  tag fix_id: 'F-55221r814176_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
