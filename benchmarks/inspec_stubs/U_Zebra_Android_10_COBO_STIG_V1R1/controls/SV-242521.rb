control 'SV-242521' do
  title 'Zebra Android 10 must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review documentation on the Zebra Android 10 device and inspect the configuration on the Zebra Android 10 device to disable multi-user modes.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open the User restrictions.
2. Open User settings.
3. Confirm "Disallow Add User" is selected.

On the Zebra Android 10 device:
1. Go to Settings >> System >> Advanced >> Multiple users.
2. Verify that there is no option to add a user.

If the MDM console device policy is not set to disable multi-user modes or on the Android 10 device, the device policy is not set to disable multi-user modes, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to disable multi-user modes.

On the MDM console:
1. Open the User restrictions.
2. Open User settings.
3. Select "Disallow Add User".'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45796r714406_chk'
  tag severity: 'medium'
  tag gid: 'V-242521'
  tag rid: 'SV-242521r714408_rule'
  tag stig_id: 'ZEBR-10-004700'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-45753r714407_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
