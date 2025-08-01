control 'SV-102969' do
  title 'Samsung Android must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review device configuration settings to confirm that the maximum number of consecutive failed authentication attempts is set to "10" or fewer. 

This procedure is performed on the MDM Administration console only. 

On the MDM console, for the device, in the "Android lock screen restrictions" group, verify that the "max password failures for local wipe" is "10" or fewer. 

If on the MDM console, "max password failures for local wipe" is more than "10", this is a finding.'
  desc 'fix', 'Configure Samsung Android to allow only 10 consecutive failed authentication attempts before device wipe. 

On the MDM console, for the device, in the "Android lock screen restrictions" group, set the "max password failures for local wipe" to "10".'
  impact 0.3
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(AE)'
  tag check_id: 'C-92187r1_chk'
  tag severity: 'low'
  tag gid: 'V-92881'
  tag rid: 'SV-102969r1_rule'
  tag stig_id: 'KNOX-09-000430'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-99125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
