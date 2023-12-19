control 'SV-250390' do
  title 'Google Android 12 must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review managed Google Android 12 device configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at ten or fewer. 

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 12 device. 

On the EMM Console:

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

On the managed Google Android 12 device:

COBO and COPE:

1. Lock the device screen.
2. Attempt to unlock the screen and validate that the device autowipes after specified number of invalid entries. Note: Perform this verification only with a test phone set up with a production profile.

If the EMM console device policy is not set to the maximum number of consecutive failed authentication attempts at ten or fewer, or if on the managed Google Android 12 device the device policy is not set to the maximum number of consecutive failed authentication attempts at ten or fewer, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to allow only 10 or fewer consecutive failed authentication attempts.

On the EMM Console:

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
  ref 'DPMS Target Google Android 12 COBO'
  tag check_id: 'C-53825r802720_chk'
  tag severity: 'medium'
  tag gid: 'V-250390'
  tag rid: 'SV-250390r802722_rule'
  tag stig_id: 'GOOG-12-006400'
  tag gtitle: 'PP-MDF-323040'
  tag fix_id: 'F-53779r802721_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
