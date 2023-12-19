control 'SV-95019' do
  title 'Samsung Android 8 with Knox must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Minimum Length" setting in the "Android Password Restrictions" rule. 
2. Verify the value of the setting is set to six or more characters.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Screen lock type".
4. Enter current password.
5. Select "Password".
6. Attempt to enter a password with fewer than six characters.
7. Verify the password is not accepted.

If the MDM console "Minimum Length" setting is not set to six characters or more or on the Samsung Android 8 with Knox device, a password of less than six characters is accepted, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce a minimum password length of six characters.

On the MDM console, set the "Minimum Length" value to "6" or greater in the "Android Password Restrictions" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79987r1_chk'
  tag severity: 'low'
  tag gid: 'V-80315'
  tag rid: 'SV-95019r1_rule'
  tag stig_id: 'KNOX-08-008300'
  tag gtitle: 'PP-MDF-301010'
  tag fix_id: 'F-87121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
