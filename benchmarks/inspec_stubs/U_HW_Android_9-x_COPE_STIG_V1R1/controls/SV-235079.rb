control 'SV-235079' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review documentation on the Honeywell Android device and inspect the configuration on the Honeywell Android device to disable multi-user modes.

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open the Restrictions settings.
2. Open User settings.
3. Confirm "Disallow Add User" is selected.

On the Honeywell Android Pie device:
1. Go to Settings >> System >> Advanced >> Multiple users.
2. Verify there is no option to add a user.

If the MDM console device policy is not set to disable multi-user modes or on the Honeywell Android Pie device, the device policy is not set to disable multi-user modes, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android Pie to disable multi-user modes.

On the MDM console:
1. Open the Restrictions settings.
2. Open User settings.
3. Select "Disallow Add User".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38298r623252_chk'
  tag severity: 'medium'
  tag gid: 'V-235079'
  tag rid: 'SV-235079r626527_rule'
  tag stig_id: 'HONW-09-004700'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-38261r623253_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
