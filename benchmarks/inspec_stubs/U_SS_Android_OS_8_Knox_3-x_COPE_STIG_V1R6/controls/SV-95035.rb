control 'SV-95035' do
  title 'Samsung Android 8 with Knox must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or fewer gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set to "10" or fewer. 

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Maximum Failed Attempts for wipe" field in the "Android Password Restrictions" rule for the device unlock password.
2. Verify the value of the setting is set to "10" or fewer.

If the MDM console "Maximum Failed Attempts for wipe" is not set to "10" or fewer, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to allow only 10 or fewer consecutive failed authentication attempts.

On the MDM console, set the "Maximum Failed Attempts for wipe" to "10" or fewer in the "Android Password Restrictions" rule for the device unlock password.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80003r1_chk'
  tag severity: 'low'
  tag gid: 'V-80331'
  tag rid: 'SV-95035r1_rule'
  tag stig_id: 'KNOX-08-009400'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-87137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
