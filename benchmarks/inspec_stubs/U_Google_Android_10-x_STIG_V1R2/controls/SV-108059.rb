control 'SV-108059' do
  title 'Google Android 10 must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review documentation on the Google Android device and inspect the configuration on the Google Android device to disable multi-user modes.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console, do the following:

1. Open the User restrictions.
2. Open user settings.
3. Confirm "Disallow Add User" is selected.

On the Android 10 device, do the following:

1. Go to Settings >> System >> Advanced >> Multiple users.
2. Ensure that there is no option to add a user.

If the MDM console device policy is not set to disable multi-user modes or on the Android 10 device, the device policy is not set to disable multi-user modes, this is a finding.'
  desc 'fix', 'Configure the Google Android 10 to disable multi-user modes.

On the MDM console:

1. Open the User restrictions.
2. Open user settings.
3. Select "Disallow Add User".'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98955'
  tag rid: 'SV-108059r1_rule'
  tag stig_id: 'GOOG-10-004700'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-104631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
