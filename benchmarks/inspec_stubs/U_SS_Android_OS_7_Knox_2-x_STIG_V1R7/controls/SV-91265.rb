control 'SV-91265' do
  title 'The Samsung Android 7 with Knox must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review documentation on the Samsung Android 7 with Knox and inspect the configuration on the Samsung Android 7 with Knox to disable multi-user modes. 
Note: This requirement is only applicable for tablet devices.

This validation procedure is performed on both the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow multi-user mode" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Attempt to add a user in the "User" setting.
3. Verify that the "User" setting is not available.

If the MDM console "Allow multi-user mode" checkbox is selected or on the Samsung Android 7 with Knox device, the user is able to add a user, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable multi-user modes.

On the MDM console, deselect the "Allow multi-user mode" setting in the "Android MultiUser" rule.

Note: This requirement is only applicable for tablet devices.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76569'
  tag rid: 'SV-91265r1_rule'
  tag stig_id: 'KNOX-07-006100'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-83263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
