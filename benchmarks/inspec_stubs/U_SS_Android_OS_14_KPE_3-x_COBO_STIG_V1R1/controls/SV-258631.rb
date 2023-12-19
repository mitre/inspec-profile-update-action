control 'SV-258631' do
  title 'Samsung Android must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or fewer attempts gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are allowing only 10 or fewer consecutive failed authentication attempts.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device password policies, verify "max password failures for local wipe" is set to "10" or fewer attempts.

On the Samsung Android device: 
1. Open Settings >> Lock screen.
2. Verify "Secure lock settings" is present and tap it.
3. Enter current password.
4. Verify "Auto factory reset" is grayed out and cannot be configured.
Note: When "Auto factory reset" is grayed out, this indicates the Administrator (MDM) is in control of the setting to wipe the device after 10 or fewer consecutive failed authentication attempts.

If on the management tool "max password failures for local wipe" is not set to "10" or fewer attempts, or on the Samsung Android device the "Auto factory reset" menu can be configured, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to allow only 10 or fewer consecutive failed authentication attempts.

On the management tool, in the device password policies, set "max password failures for local wipe" to "10" or fewer attempts.

A device password must be set for "max password failures for local wipe" to become active.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62371r931091_chk'
  tag severity: 'medium'
  tag gid: 'V-258631'
  tag rid: 'SV-258631r931093_rule'
  tag stig_id: 'KNOX-14-110060'
  tag gtitle: 'PP-MDF-333040'
  tag fix_id: 'F-62280r931092_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
