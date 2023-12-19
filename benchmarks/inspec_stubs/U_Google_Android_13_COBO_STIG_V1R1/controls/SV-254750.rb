control 'SV-254750' do
  title 'Google Android 13 must be configured to disable multiuser modes.'
  desc 'Multiuser mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multiuser mode features meets DOD requirements for access control, data separation, and nonrepudiation for user accounts. In addition, the MDFPP does not include design requirements for multiuser account services. Disabling multiuser mode mitigates the risk of not meeting DOD multiuser account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47a'
  desc 'check', 'Review documentation on the managed Google Android 13 device and inspect the configuration on the Google Android device to disable multiuser modes.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device. 

On the EMM console:

COBO and COPE: 

1. Open "User restrictions".
2. Open "Set user restrictions".
3. Verify "Disallow modify accounts" is toggled to "ON".

On the managed Google Android 13 device:

COBO and COPE:

1. Go to Settings >> Passwords & accounts >> Accounts for Owner.
2. Tap "Add account".
3. Verify the action is not allowed.

If the EMM console device policy is not set to disable multi-user modes or on the managed Google Android 13 device, the device policy is not set to disable multi-user modes, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable multi-user modes.

On the EMM console:

COBO and COPE:

1. Open "User restrictions".
2. Open "Set user restrictions".
3. Toggle "Disallow modify accounts" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58361r862447_chk'
  tag severity: 'medium'
  tag gid: 'V-254750'
  tag rid: 'SV-254750r862449_rule'
  tag stig_id: 'GOOG-13-009000'
  tag gtitle: 'PP-MDF-323290'
  tag fix_id: 'F-58307r862448_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
