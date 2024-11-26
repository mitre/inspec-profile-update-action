control 'SV-255171' do
  title 'Microsoft Android 11 must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at 10 or fewer. 

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max password failures for local wipe" is set to a number between 1 and 10.

On the Microsoft Android 11 device:
Lock the device screen, then attempt to unlock the screen and validate that the device autowipes after specified number if invalid entries.

If the EMM console device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, or if on the Android 11 device the device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to allow only 10 or fewer consecutive failed authentication attempts.

On the EMM console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max password failures for local wipe" to a number between 1 and 10.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58784r870651_chk'
  tag severity: 'medium'
  tag gid: 'V-255171'
  tag rid: 'SV-255171r870653_rule'
  tag stig_id: 'MSFT-11-000500'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-58728r870652_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
