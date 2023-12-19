control 'SV-231016' do
  title 'Samsung Android must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at 10 or less. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool:
1. Open the device password policies.
2. Verify "minimum password quality" is set to "Numeric" (or better).
3. Verify the "max password failures for local wipe" is set to "10" attempts or less.

On the Samsung Android device: 
1. Open Settings >> Lock screen.
2. Verify "Secure lock settings" is present and tap it.
3. Enter current password.
4. Verify that "Auto factory reset" menu is disabled.

If on the management tool the "minimum password quality" is not set to "Numeric" (or better) and "max password failures for local wipe" is not set to "10" attempts or less, or on the Samsung Android device the "Auto factory reset" menu is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to allow only 10 or fewer consecutive failed authentication attempts.

On the management tool:
1. Open the device password policies.
2. Set "minimum password quality" to "Numeric" (or better).
3. Set the "max password failures for local wipe" to "10" attempts or less.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33946r592662_chk'
  tag severity: 'medium'
  tag gid: 'V-231016'
  tag rid: 'SV-231016r608683_rule'
  tag stig_id: 'KNOX-11-000800'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-33919r592663_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
