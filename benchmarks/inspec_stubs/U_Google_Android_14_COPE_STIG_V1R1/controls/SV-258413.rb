control 'SV-258413' do
  title 'Google Android 14 must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at 10 or fewer. 

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 14 device. 

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Verify that "Max password failures for local wipe" is set to a number between 1 and 10.

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Personal Profile".
4. Verify that "Max password failures for local wipe" is set to a number between 1 and 10.
_________________________

On the managed Google Android 14 device:

COBO and COPE:

1. Lock the device screen.
2. Attempt to unlock the screen and validate that the device autowipes after specified number of invalid entries. Note: Perform this verification only with a test phone set up with a production profile.

If the EMM console device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, or if on the managed Google Android 14 device the device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to allow only 10 or fewer consecutive failed authentication attempts.

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Set "Max password failures for local wipe" to a number between 1 and 10.

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Personal Profile".
4. Set "Max password failures for local wipe" to a number between 1 and 10.'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62154r928262_chk'
  tag severity: 'medium'
  tag gid: 'V-258413'
  tag rid: 'SV-258413r928264_rule'
  tag stig_id: 'GOOG-14-006400'
  tag gtitle: 'PP-MDF-333040'
  tag fix_id: 'F-62078r928263_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
