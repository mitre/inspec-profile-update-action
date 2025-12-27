control 'SV-235039' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at 10 or fewer. 

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Review the policy configuration that was pushed down to the device and ensure the "Maximum Number of Failed Attempts" is set between 1 and 10.

On the Honeywell Android Pie device:
1. Open Setting >> Security & location >> Advanced >> Managed device info.
2. Verify "Failed password attempts before deleting all device data" is set to 10 or fewer attempts.

If the MDM console device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer or on the Honeywell Android Pie device, the device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to allow only 10 or fewer consecutive failed authentication attempts.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Set "Maximum Number of Failed Attempts" to a number between 1 and 10.'
  impact 0.3
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38227r623027_chk'
  tag severity: 'low'
  tag gid: 'V-235039'
  tag rid: 'SV-235039r626530_rule'
  tag stig_id: 'HONW-09-000500'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-38190r623028_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
