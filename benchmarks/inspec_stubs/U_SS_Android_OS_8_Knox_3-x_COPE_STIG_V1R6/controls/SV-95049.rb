control 'SV-95049' do
  title 'Samsung Android 8 with Knox must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Note: This requirement is only applicable for tablet devices.

Review documentation on Samsung Android 8 with Knox and inspect the configuration on Samsung Android 8 with Knox to disable multi-user modes.

This validation procedure is performed on the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow multi-user mode" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Attempt to add a user in the "User" setting.
3. Verify that the "User" setting is not available.

If the MDM console "Allow multi-user mode" check box is selected or on the Samsung Android 8 with Knox device, the user is able to add a user, this is a finding.'
  desc 'fix', 'Note: This requirement is only applicable for tablet devices.

Configure the Samsung Android 8 with Knox to disable multi-user modes.

On the MDM console, deselect the "Allow multi-user mode" setting in the "Android MultiUser" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80345'
  tag rid: 'SV-95049r1_rule'
  tag stig_id: 'KNOX-08-013000'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-87151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
