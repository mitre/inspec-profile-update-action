control 'SV-95037' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure to prohibit more than 10 consecutive failed CONTAINER authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or fewer gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing 10 or fewer failed CONTAINER authentication attempts.

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Maximum Failed Attempts for wipe" field in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule.
2. Verify the value of the setting is "10" or fewer.

If the MDM console "Maximum Failed Attempts for wipe" is not set to "10" or fewer or on the Samsung Android 8 with Knox device, the user is able to fail more than 10 authentication attempts, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce 10 or fewer failed CONTAINER authentication attempts.

On the MDM console, set the "Maximum Failed Attempts for wipe" to the organization-defined value in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80005r1_chk'
  tag severity: 'low'
  tag gid: 'V-80333'
  tag rid: 'SV-95037r1_rule'
  tag stig_id: 'KNOX-08-009500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
