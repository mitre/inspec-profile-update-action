control 'SV-228609' do
  title 'Google Android 11 must be configured to not allow more than ten consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password, but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at ten or fewer. 

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM Console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max password failures for local wipe" is set to a number between 1 and 10.

On the Android 11 device, do the following:
1. Lock the device screen.
2. Attempt to unlock the screen and validate that the device autowipes after specified number of invalid entries.

If the EMM console device policy is not set to the maximum number of consecutive failed authentication attempts at ten or fewer, or if on the Android 11 device the device policy is not set to the maximum number of consecutive failed authentication attempts at ten or fewer, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to allow only 10 or fewer consecutive failed authentication attempts.

On the EMM Console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max password failures for local wipe" to a number between 1 and 10.'
  impact 0.3
  ref 'DPMS Target Google Android 11 COPE'
  tag check_id: 'C-30844r505824_chk'
  tag severity: 'low'
  tag gid: 'V-228609'
  tag rid: 'SV-228609r505826_rule'
  tag stig_id: 'GOOG-11-000500'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-30821r505825_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
